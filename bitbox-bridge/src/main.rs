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
use std::net::SocketAddr;
use tokio::runtime::Runtime;

#[macro_use]
extern crate log;

#[cfg(target_os = "windows")]
#[path = "daemon/windows.rs"]
mod daemon;

#[cfg(not(target_os = "windows"))]
#[path = "daemon/unix.rs"]
mod daemon;

mod error;
mod usb;
mod web;

use usb::UsbDevices;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // On some platforms it is necessary to inform that you are a daemon and will run in the
    // background. The `start()` function returns a future that completes if the platform requests
    // the service to stop.
    let stop_request = daemon::start();

    // Check if the user requested some specific log level via an env variable. Otherwise set log
    // level to something reasonable.
    if std::env::var("RUST_LOG").is_ok() {
        env_logger::init();
    } else {
        env_logger::Builder::new()
            .filter_level(log::LevelFilter::Info)
            .init();
    }
    println!("Set RUST_LOG=<filter> to enable logging. Example RUST_LOG=debug");

    // Parse CLI args
    let matches = clap::Command::new("BitBoxBridge")
        .version(clap::crate_version!())
        .arg(
            clap::Arg::new("port")
                .value_parser(clap::value_parser!(u16))
                .long("port")
                .short('p')
                .default_value("8178"),
        )
        .get_matches();

    // Unwrap shouldn't happen since it has a default value
    let port = *matches.get_one("port").unwrap();
    // Create an async runtime for spawning futures on
    let rt = Runtime::new()?;

    // Create the global state that can be shared between threads
    let usb_devices = UsbDevices::new()?;

    // Create a channel with which it is possible to request a refresh of usb devices. A length of
    // 1 is enough since it doesn't make sense to request more refreses than the refresh task can
    // execute.
    let (mut notify_tx, notify_rx) = mpsc::channel(1);
    // Trigger one refresh on startup
    web::notify(&mut notify_tx);

    // Create and spawn the future that polls for USB devices
    let usb_poller = {
        let usb_devices = usb_devices.clone();
        async move {
            if let Err(e) = usb_devices.presence_detector(notify_rx).await {
                error!("Stopped polling for usb devices: {}", e);
            }
        }
    };

    let addr = SocketAddr::new("127.0.0.1".parse()?, port);

    println!("listening on http://{}", addr);
    let server = web::create(usb_devices, notify_tx, addr);

    rt.block_on(async move {
        tokio::select! {
            _ = stop_request => info!("Requested to stop by environment"),
            _ = server => info!("Warp returned"),
            _ = usb_poller => info!("Usb poller died"),
        }
    });

    Ok(())
}
