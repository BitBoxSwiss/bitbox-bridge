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

use std::ffi::OsString;
use std::time::Duration;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

define_windows_service!(ffi_service_main, my_service_main);

/// Gets called when service is started
/// Is run in a background thread
fn my_service_main(args: Vec<OsString>) {
    if let Err(e) = run_service(args) {
        error!("Service control communication failed: {:?}", e);
    }
}

fn run_service(_args: Vec<OsString>) -> Result<(), windows_service::Error> {
    let (tx, rx) = std::sync::mpsc::channel();
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop => {
                // Handle stop event and return control back to the system.
                tx.send(()).unwrap();
                ServiceControlHandlerResult::NoError
            }
            // All services must accept Interrogate even if it's a no-op.
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    // Register system service event handler
    let status_handle = service_control_handler::register("bitbox-bridge", event_handler)?;

    // Tell the system that the service is running now
    status_handle.set_service_status(ServiceStatus {
        // Should match the one from system service registry
        service_type: ServiceType::OWN_PROCESS,
        // The new state
        current_state: ServiceState::Running,
        // Accept stop events when running
        controls_accepted: ServiceControlAccept::STOP,
        // Used to report an error when starting or stopping only, otherwise must be zero
        exit_code: ServiceExitCode::Win32(0),
        // Only used for pending states, otherwise must be zero
        checkpoint: 0,
        // Only used for pending states, otherwise must be zero
        wait_hint: Duration::default(),
    })?;

    // Poll shutdown event.
    rx.recv().unwrap();

    // Tell the system that service has stopped.
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
    })?;

    Ok(())
}

/// start interacting as a service / daemon
pub async fn start() {
    let (tx, rx) = futures::channel::oneshot::channel();
    std::thread::spawn(move || {
        // Blocking call, will block until service is killed by Winows
        if let Err(e) = service_dispatcher::start("bitbox-bridge", ffi_service_main) {
            error!("Failed to register as started service: {:?}", e);
            tx.send(false).unwrap();
            return;
        }
        tx.send(true).unwrap();
    });
    let res = rx.await.unwrap();
    if !res {
        // This task will forever wait here since we coulnd't communicate with the windows service manager
        futures::future::pending::<()>().await;
    }
}
