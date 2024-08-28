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

use futures::channel::{mpsc, oneshot};
use futures::prelude::*;
use futures_util::sink::SinkExt;
use percent_encoding::percent_decode_str;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use warp::{self, Filter, Rejection, Reply};

use crate::error::WebError;
use crate::usb::UsbDevices;

async fn list_devices(
    usb_devices_tx: (UsbDevices, mpsc::Sender<()>),
) -> Result<impl warp::Reply, Rejection> {
    let (usb_devices, mut tx) = usb_devices_tx;
    notify(&mut tx);
    let v = usb_devices.devices().await;
    let mut map = HashMap::new();
    map.insert("devices", v);
    let reply = warp::reply::json(&map);
    Ok(reply)
}

async fn show_info() -> Result<impl warp::Reply, Rejection> {
    let mut map = HashMap::new();
    map.insert("version", clap::crate_version!());
    Ok(warp::reply::json(&map))
}

// Only accept connections to the virtual host "localhost"
fn is_valid_host(host: &str) -> bool {
    host == "localhost" || host == "127.0.0.1"
}

// Only accept websocket connections where the origin is "localhost" or from our domain
fn is_valid_origin(host: &str) -> bool {
    host == "localhost"
        || host == "127.0.0.1"
        || host.ends_with(".shiftcrypto.ch")
        || host.ends_with(".digitalbitbox.com")
        || host == "digitalbitbox.com"
        || host.ends_with(".bity.com")
        || host == "bity.com"
        || host.ends_with(".myetherwallet.com")
        || host == "myetherwallet.com"
        || host.ends_with(".pocketbitcoin.com")
        || host == "pocketbitcoin.com"
        || host.ends_with(".adalite.io")
        || host == "adalite.io"
}

fn add_origin(
    reply: impl warp::Reply + 'static,
    origin: Option<String>,
) -> Box<dyn warp::Reply + 'static> {
    match origin {
        Some(origin) => {
            let reply = warp::reply::with_header(reply, "Access-Control-Allow-Origin", origin);
            Box::new(warp::reply::with_header(reply, "Vary", "Origin"))
        }
        None => Box::new(reply),
    }
}

// Try to notify other task that we've had activity,
// ignore if channel already contained notification.
pub fn notify(tx: &mut mpsc::Sender<()>) {
    match tx.try_send(()) {
        Err(e) if e.is_disconnected() => debug!("Channel was closed"),
        Err(e) if e.is_full() => (),
        _ => (),
    }
}

async fn ws_upgrade(
    path: String,
    ws: warp::ws::Ws,
    usb_devices_tx: (UsbDevices, mpsc::Sender<()>),
) -> Result<impl warp::Reply, Rejection> {
    let path = match percent_decode_str(&path).decode_utf8() {
        Ok(path) => path.into_owned(),
        Err(e) => {
            error!("Failed to decode string: {}", e);
            return Err(warp::reject::custom(WebError::NoSuchDevice));
        }
    };
    let (usb_devices, mut tx) = usb_devices_tx;
    notify(&mut tx);
    let (mut dev_tx, mut dev_rx) = usb_devices
        .acquire_device(&path)
        .await
        .map_err(|_e| warp::reject::custom(WebError::NoSuchDevice))?
        .ok_or_else(|| warp::reject::custom(WebError::NoSuchDevice))?;
    Ok(ws.on_upgrade({
        let mut notify_tx = tx.clone();
        move |websocket| {
            async move {
                let (mut ws_tx, mut ws_rx) = websocket.split();
                tokio::spawn(async move {
                    while let Some(data) = dev_rx.next().await {
                        info!("WS TX: {:?}", data);
                        if let Err(e) = ws_tx.send(warp::ws::Message::binary(data)).await {
                            warn!("Failed, connection closed? {}", e);
                            break;
                        }
                    }
                    match ws_tx.close().await {
                        Ok(_) => debug!("closed ok"),
                        Err(_) => debug!("closed err"),
                    };
                });
                while let Some(msg) = ws_rx.next().await {
                    notify(&mut notify_tx);
                    match msg {
                        Ok(buf) => {
                            info!("WS RX: {:?}", buf);
                            if buf.is_close() {
                                // Connection closed, close internal channel
                                if let Err(_e) = dev_tx.close().await {
                                    error!("failed to close dev tx");
                                }
                                return;
                            }
                            if buf.is_binary() {
                                if let Err(e) = dev_tx.send(Vec::from(buf.as_bytes())).await {
                                    warn!("Failed to send to device {:?}", e);
                                }
                            }
                            if buf.is_ping() {
                                debug!("Got ping, nothing todo");
                            }
                        }
                        Err(e) => {
                            error!("WS RX: {:?}", e);
                            return;
                        }
                    }
                }
            }
        }
    }))
}

// Global state to store the current oneshot sender
struct ConfirmState {
    sender: Mutex<HashMap<String, (oneshot::Sender<bool>, String)>>,
}

impl ConfirmState {
    fn new() -> Arc<Self> {
        Arc::new(ConfirmState {
            sender: Mutex::new(HashMap::new()),
        })
    }
}

fn with_state<T: Clone + Send>(
    state: T,
) -> impl Filter<Extract = (T,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || state.clone())
}

#[derive(Clone)]
struct AllowedHosts(Arc<Mutex<HashSet<String>>>);

impl AllowedHosts {
    fn new() -> AllowedHosts {
        AllowedHosts(Arc::new(Mutex::new(HashSet::new())))
    }
}

// On windows, we use a native system dialog to prompt the user.
// The browser based prompt does not work as we can't launch a browser from the service (not allowed).
//
// We use WTSSendMessage as officially recommended (it recommends WTSSendMessageA, the ANSI-encoded
// version, but WTSSendMessagW for UTF-16 also works):
//
// See https://learn.microsoft.com/en-us/windows/win32/services/interactive-services
// > You can use the following techniques to interact with the user from a service on all supported versions of Windows:
// > Display a dialog box in the user's session using the [WTSSendMessage](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtssendmessagea) function.
#[cfg(target_os = "windows")]
async fn user_confirm(
    _confirm_state: Arc<ConfirmState>,
    message: String,
    _base_url: &str,
) -> Result<bool, ()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::System::RemoteDesktop::{
        WTSGetActiveConsoleSessionId, WTSSendMessageW, WTS_CURRENT_SERVER_HANDLE,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{IDYES, MB_YESNO, MESSAGEBOX_RESULT};

    fn utf8_to_utf16(s: &str) -> Vec<u16> {
        std::ffi::OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    let title_c = utf8_to_utf16("BitBoxBridge");
    let message_c = utf8_to_utf16(&message);

    let mut response: MESSAGEBOX_RESULT = 0;
    let timeout: u32 = 60; // 60 seconds

    unsafe {
        // Need the active user session ID so the dialog is shown to the user.
        let current_session = WTSGetActiveConsoleSessionId();
        if current_session == 0xFFFFFFFF {
            // See https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-wtsgetactiveconsolesessionid#return-value
            return Err(());
        }
        let result = WTSSendMessageW(
            WTS_CURRENT_SERVER_HANDLE,
            current_session,
            title_c.as_ptr(),
            // Each element is 2 bytes except, including the the null terminator
            (title_c.len() * 2) as u32,
            message_c.as_ptr(),
            (message_c.len() * 2) as u32,
            MB_YESNO,
            timeout,
            &mut response,
            1,
        );

        if result == 0 {
            return Err(());
        }
    }

    // Check if the user clicked 'Yes'
    Ok(response == IDYES)
}

// On Linux/maCOS, we launch a browser with a prompt.
//
// On macOS, native dialogs don't work if there is no main window (we don't have one, it's a service).
//
// On linux, native dialogs would work, but we use the browser based solution here too as native
// dialogs might not work in all distros/configs.
#[cfg(not(target_os = "windows"))]
async fn user_confirm(
    confirm_state: Arc<ConfirmState>,
    message: String,
    base_url: &str,
) -> Result<bool, ()> {
    let (tx, rx) = oneshot::channel();
    let confirm_id = uuid::Uuid::new_v4();
    {
        let mut sender = confirm_state.sender.lock().unwrap();
        sender.insert(confirm_id.to_string(), (tx, message));
    }

    // Launch the web browser to show the dialog
    let dialog_url = format!("{}/confirm/{}", base_url, confirm_id);
    if webbrowser::open(&dialog_url).is_err() {
        return Err(());
    }

    // Wait for the user's response from the HTTP handler
    rx.await.map_err(|_| ())
}

async fn user_confirm_origin(
    confirm_state: Arc<ConfirmState>,
    allowed_hosts: AllowedHosts,
    host: &str,
    base_url: &str,
) -> Result<bool, ()> {
    // Early return for whitelisted hosts.
    if is_valid_origin(host) {
        return Ok(true);
    }
    {
        // Early return if the origin was previously allowed/accepted by the user.
        if allowed_hosts.0.lock().unwrap().contains(host) {
            return Ok(true);
        }
    }
    let result = user_confirm(
        confirm_state,
        format!("Allow {} to connect to your BitBox?", host),
        base_url,
    )
    .await?;
    if result {
        allowed_hosts.0.lock().unwrap().insert(host.into());
    }
    Ok(result)
}

fn setup_confirm_routes(
    confirm_state: Arc<ConfirmState>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let confirm_dialog = warp::path!("confirm" / String)
        .and(warp::get())
        .and(with_state(confirm_state.clone()))
        .map(|confirm_id: String, confirm_state: Arc<ConfirmState>| {
            let sender_locked = confirm_state.sender.lock().unwrap();
            if let Some((_, message)) = sender_locked.get(&confirm_id) {
                let html = include_str!("../resources/confirmation_dialog.html");
                let ctx = {
                    let mut ctx = tera::Context::new();
                    ctx.insert("confirm_id", &confirm_id);
                    ctx.insert("message", &message);
                    ctx
                };
                let body = match tera::Tera::one_off(html, &ctx, true) {
                    Ok(reply) => reply,
                    Err(_) => "Could not render tera template".into(),
                };
                warp::reply::html(body).into_response()
            } else {
                // No user confirmation active.
                warp::reply::with_status("", warp::http::StatusCode::BAD_REQUEST).into_response()
            }
        });

    async fn handle_user_response(
        confirm_id: String,
        choice: bool,
        confirm_state: Arc<ConfirmState>,
    ) -> Result<impl warp::Reply, warp::Rejection> {
        if let Some((sender, _)) = confirm_state.sender.lock().unwrap().remove(&confirm_id) {
            let _ = sender.send(choice);

            Ok(warp::reply::with_status("", warp::http::StatusCode::OK))
        } else {
            Ok(warp::reply::with_status(
                "",
                warp::http::StatusCode::BAD_REQUEST,
            ))
        }
    }

    let handle_response = warp::path!("confirm" / "response" / String / bool)
        .and(warp::post())
        .and(with_state(confirm_state.clone()))
        .and_then(handle_user_response);

    handle_response.or(confirm_dialog)
}

pub async fn create(usb_devices: UsbDevices, notify_tx: mpsc::Sender<()>, addr: SocketAddr) {
    let confirm_state = ConfirmState::new();
    let allowed_hosts = AllowedHosts::new();

    // create a warp filter out of "usb_devices" to pass it into our handlers later
    let usb_devices = warp::any().map(move || (usb_devices.clone(), notify_tx.clone()));

    // Only accept local connections
    // Use untuple_one at the end to get rid of the "unit" return value
    let only_local_ip = warp::addr::remote()
        .and_then(|addr: Option<SocketAddr>| {
            debug!("{:?}", addr);
            async move {
                if let Some(addr) = addr {
                    if addr.ip().is_loopback() {
                        info!("Client connected: {:?}", addr);
                        return Ok(());
                    }
                }
                Err(warp::reject::custom(WebError::NonLocalIp))
            }
        })
        .untuple_one();

    // Only accept localhost / 127.0.0.1 as vhosts
    // Use untuple_one at the end to get rid of the "unit" return value
    let only_local_vhost = warp::header("host")
        .and_then(|header_host: hyper::Uri| {
            debug!("{:?}", header_host);
            async move {
                if let Some(host) = header_host.host() {
                    if !is_valid_host(host) {
                        warn!("Server tried to be accessed through non-supported host");
                        return Err(warp::reject::custom(WebError::InvalidVirtualHost));
                    }
                    return Ok(());
                }
                Err(warp::reject::custom(WebError::InvalidVirtualHost))
            }
        })
        .untuple_one();

    // Only accept some origin
    // Use untuple_one at the end to get rid of the "unit" return value
    let check_origin = warp::header::optional("origin")
        .and(with_state(confirm_state.clone()))
        .and(with_state(allowed_hosts))
        .and(with_state(addr))
        .and_then(
            |origin: Option<hyper::Uri>,
             confirm_state: Arc<ConfirmState>,
             allowed_hosts: AllowedHosts,
             addr| {
                debug!("Origin: {:?}", origin);
                async move {
                    if let Some(origin) = origin {
                        let scheme_str = origin.scheme_str();
                        if scheme_str == Some("chrome-extension")
                            || scheme_str == Some("moz-extension")
                        {
                            debug!("Allow Chrome/Firefox extension");
                            return Ok(());
                        }
                        match origin.host() {
                            Some(host) => {
                                if !user_confirm_origin(
                                    confirm_state,
                                    allowed_hosts,
                                    host,
                                    &format!("http://{}", addr),
                                )
                                .await
                                .unwrap()
                                {
                                    warn!("Not whitelisted origin tried to connect: {}", host);
                                    return Err(warp::reject::custom(WebError::NonLocalIp));
                                }
                            }
                            None => {
                                warn!("Not whitelisted origin tried to connect");
                                return Err(warp::reject::custom(WebError::NonLocalIp));
                            }
                        }
                    }
                    // If there is no `origin` header, it must mean that the connection is from
                    // a website hosted by ourselves. Which is fine.
                    Ok(())
                }
            },
        )
        .untuple_one();

    let opt_origin = warp::header::optional("origin");

    // path segments for /api/v1
    let api = warp::path("api");
    let v1_root = api.and(warp::path("v1"));

    // path segments for /socket/:param
    let websocket = warp::path("socket")
        .and(warp::path::param())
        .and(warp::path::end());

    // path segment for info
    let info = warp::path("info").and(warp::path::end());

    // path segment for devices
    let devices = warp::path("devices").and(warp::path::end());

    // `GET /`
    let root = warp::path::end().map({
        move || {
            let html = include_str!("../resources/index.html");
            let ctx = {
                let mut ctx = tera::Context::new();
                ctx.insert("version", clap::crate_version!());
                ctx.insert("addr", &addr);
                ctx
            };
            let body = match tera::Tera::one_off(html, &ctx, true) {
                Ok(reply) => reply,
                Err(_) => "Could not render tera template".into(),
            };
            warp::reply::html(body)
        }
    });

    // `GET /api/v1/socket/:socket`
    let websocket = warp::get()
        .and(v1_root)
        .and(websocket)
        .and(check_origin.clone())
        .and(warp::ws())
        .and(usb_devices.clone())
        .and_then(ws_upgrade);

    // `GET /api/v1/devices`
    let devices = warp::get()
        .and(v1_root)
        .and(devices)
        .and(check_origin.clone())
        .and(usb_devices)
        .and_then(list_devices)
        .and(opt_origin)
        .map(add_origin);

    // `GET /api/info`
    let info = warp::get()
        .and(api)
        .and(info)
        .and(check_origin.clone())
        .and_then(show_info)
        .and(opt_origin)
        .map(add_origin);

    let confirm_routes = setup_confirm_routes(confirm_state.clone());
    // combine routes
    let routes = only_local_ip
        .and(only_local_vhost)
        .and(websocket.or(devices).or(root).or(info).or(confirm_routes))
        .recover(|err: warp::Rejection| {
            async {
                if let Some(err) = err.find::<WebError>() {
                    let reply = match err {
                        // We return 423 Locked if the device is already taken
                        WebError::NoSuchDevice => warp::http::Response::builder()
                            .status(warp::http::StatusCode::LOCKED)
                            .body("Device locked"),
                        // We return 403 Forbidden for all other errors:
                        // The request was valid, but the server is refusing action. The user might not
                        // have the necessary permissions for a resource, or may need an account of
                        // some sort.
                        _ => warp::http::Response::builder()
                            .status(warp::http::StatusCode::FORBIDDEN)
                            .body("Not allowed"),
                    };
                    // Allow anyone to see error messages
                    let reply = warp::reply::with_header(reply, "Access-Control-Allow-Origin", "*");
                    Ok(reply)
                } else {
                    Err(err)
                }
            }
        });
    warp::serve(routes).run(addr).await
}
