// Copyright 2020 Shift Cryptosecurity AG
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use futures::channel::mpsc;
use futures::channel::oneshot;
use futures::lock::Mutex;
use futures::prelude::*;
use hidapi::HidApi;
use hidapi_async::Device;
use std::collections::{hash_map::Entry, HashMap};
use std::sync::Arc;
use std::time::Duration;
use std::time::SystemTime;
use u2fframing::{U2FFraming, U2FHID, U2FWS};

struct DeviceEntry {
    acquired: DeviceAcquiredState,
    product: String,
}

enum DeviceAcquiredState {
    Available,
    Acquired(mpsc::Sender<oneshot::Sender<()>>),
}

impl std::fmt::Debug for DeviceEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        match &self.acquired {
            DeviceAcquiredState::Available => write!(f, "Avilable ({})", self.product)?,
            DeviceAcquiredState::Acquired { .. } => write!(f, "Acquired")?,
        }
        Ok(())
    }
}

impl DeviceEntry {
    pub fn new(product: &str) -> Self {
        DeviceEntry {
            acquired: DeviceAcquiredState::Available,
            product: product.to_string(),
        }
    }

    pub fn product(&self) -> &str {
        &self.product
    }

    pub fn acquire(&mut self, tx: mpsc::Sender<oneshot::Sender<()>>) {
        self.acquired = DeviceAcquiredState::Acquired(tx);
    }

    pub async fn release(&mut self) {
        match &mut self.acquired {
            DeviceAcquiredState::Acquired(tx) => {
                // We use a oneshot channel to communicate that the device has been successfully
                // dropped. The "device_loop" task will first drop the device and then drop this
                // Sender.
                let (close_tx, close_rx) = oneshot::channel();
                if let Err(_e) = tx.send(close_tx).await {
                    error!("failed to send");
                }
                let _ = close_rx.await; // Error here is expected
            }
            _ => (),
        }
        self.acquired = DeviceAcquiredState::Available;
    }
}

pub struct USBDevices {
    devices: Arc<Mutex<HashMap<String, DeviceEntry>>>,
    hidapi: Arc<Mutex<HidApi>>,
}

impl Clone for USBDevices {
    fn clone(&self) -> Self {
        USBDevices {
            devices: Arc::clone(&self.devices),
            hidapi: Arc::clone(&self.hidapi),
        }
    }
}

impl USBDevices {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(USBDevices {
            devices: Default::default(),
            hidapi: Arc::new(Mutex::new(HidApi::new()?)),
        })
    }
    pub async fn devices(&self) -> Vec<HashMap<String, String>> {
        self.devices
            .lock()
            .await
            .iter()
            .map(|device| {
                let mut d = HashMap::new();
                d.insert(
                    "path".into(),
                    percent_encoding::utf8_percent_encode(
                        &device.0,
                        percent_encoding::NON_ALPHANUMERIC,
                    )
                    .to_string(),
                );
                d.insert("product".into(), device.1.product().to_string());
                d
            })
            .collect()
    }

    pub async fn presence_detector(
        self,
        mut notify_rx: mpsc::Receiver<()>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        loop {
            // Wait here until we are notified of new request
            let _ = notify_rx.next().await;
            info!("Notified!");
            let mut last_seen = None;
            loop {
                self.refresh().await?;

                // Stop iterating in case wallets are plugged out and there haven't been any
                // communication in a while.
                if self.devices.lock().await.len() == 0 {
                    match last_seen {
                        None => last_seen = Some(SystemTime::now()),
                        Some(last_seen) => {
                            if last_seen.elapsed()? > Duration::from_secs(5) {
                                break;
                            }
                        }
                    }
                } else {
                    last_seen = None;
                }
                tokio::time::delay_for(Duration::from_millis(200)).await;
            }
        }
    }

    pub async fn refresh(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.hidapi.lock().await.refresh_devices()?;
        let mut seen = Vec::new();
        let mut devices_guard = self.devices.lock().await;
        for device in self.hidapi.lock().await.devices() {
            // TODO(nc): On windows interface_number is -1. How to distinguish hww?
            if device.vendor_id == 0x03eb
                && device.product_id == 0x2403
                && (device.interface_number == 0 || device.interface_number == -1)
            {
                let path = match device.path.as_ref().to_str() {
                    Ok(path) => path,
                    Err(e) => {
                        warn!("ignored: {}", e);
                        continue;
                    }
                };
                let product = match device.product_string.as_ref() {
                    Some(product) => product,
                    None => {
                        warn!("ignored: no product");
                        continue;
                    }
                };
                seen.push(path.to_string());
                match devices_guard.entry(path.to_string()) {
                    Entry::Occupied(_) => (),
                    Entry::Vacant(v) => {
                        info!("Found BitBox02 at {}!", path);
                        v.insert(DeviceEntry::new(&product));
                    }
                }
            }
        }
        // Remove all devices that wasn't seen
        devices_guard.retain(|k, _| seen.contains(&k));
        Ok(())
    }

    pub async fn acquire_device(
        &self,
        path: &str,
    ) -> Result<Option<(mpsc::Sender<Vec<u8>>, mpsc::Receiver<Vec<u8>>)>, Box<dyn std::error::Error>>
    {
        if let Some(device) = self.devices.lock().await.get_mut(path) {
            // Make sure device is released
            device.release().await;

            let (in_tx, in_rx) = mpsc::channel(128);
            let (out_tx, out_rx) = mpsc::channel(128);
            let path_cstr = std::ffi::CString::new(&path[..])?;
            let hiddevice = self.hidapi.lock().await.open_path(&path_cstr)?;
            let hiddevice = Device::new(hiddevice)?;
            info!("Successfully acquired device: {}", path);
            let (on_close_tx, on_close_rx) = mpsc::channel(1);
            device.acquire(on_close_tx);
            tokio::spawn(device_loop(hiddevice, in_rx, out_tx, on_close_rx));
            Ok(Some((in_tx, out_rx)))
        } else {
            Ok(None)
        }
    }
}

async fn handle_msg(
    device: &mut Device,
    msg: Vec<u8>,
    out_tx: &mut mpsc::Sender<Vec<u8>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (cid, cmd, _) = u2fframing::parse_header(&msg[..])?;

    let mut wscodec = U2FWS::with_cid(cid, cmd);
    let res = wscodec.decode(&msg[..])?.ok_or(std::io::Error::new(
        std::io::ErrorKind::Other,
        "not enough data in websocket message",
    ))?;

    let mut hidcodec = U2FHID::new(cmd);
    let mut buf = [0u8; 7 + 7609]; // Maximally supported size by u2f
    let len = hidcodec.encode(&res[..], &mut buf[..])?;

    device.write_all(&buf[..len]).await?;

    let mut len = 0;
    loop {
        let this_len = device.read(&mut buf[len..]).await?;
        len += this_len;
        let res = hidcodec.decode(&buf[..len])?;
        if let Some(res) = res {
            if let Ok(len) = wscodec.encode(&res[..], &mut buf[..]) {
                if let Err(e) = out_tx.send(buf[..len].to_vec()).await {
                    error!("Failed to send internally: {}", e);
                }
            }
            break;
        }
        // Loop to read out more data from device
    }
    Ok(())
}

async fn device_loop(
    mut device: Device,
    mut in_rx: mpsc::Receiver<Vec<u8>>,
    mut out_tx: mpsc::Sender<Vec<u8>>,
    mut on_close_rx: mpsc::Receiver<oneshot::Sender<()>>,
) {
    loop {
        tokio::select! {
            msg = in_rx.next() => {
                if let Some(msg) = msg {
                    if let Err(e) = handle_msg(&mut device, msg, &mut out_tx).await {
                        error!("message ignored: {}", e);
                    }
                } else {
                    error!("dev channel closed");
                    return;
                }
            },
            close_tx = on_close_rx.next() => {
                if let Some(_close_tx) = close_tx {
                    // We drop the device explitly so that it is dropped before the Sender we were sent
                    drop(device);
                } else {
                    // When the device is plugged out, the other end of the channel will be dropped and
                    // then this future will resolve to None since the stream has ended.
                    info!("Device was plugged out");
                }
                return;
            }
        }
    }
}
