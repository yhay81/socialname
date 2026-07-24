#![forbid(unsafe_code)]

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use serde::Serialize;
use socialname_app_core::{AppCore, SearchCompletion, SearchEvent, SearchRequest, SiteSummary};
use tauri::{State, ipc::Channel};
use tokio_util::sync::CancellationToken;

struct DesktopState {
    core: Arc<AppCore>,
    active_searches: Mutex<BTreeMap<String, CancellationToken>>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AppInfo {
    version: &'static str,
    execution_mode: &'static str,
    synchronization: &'static str,
    rule_pack_hash: String,
}

#[tauri::command]
fn get_app_info(state: State<'_, DesktopState>) -> AppInfo {
    AppInfo {
        version: env!("CARGO_PKG_VERSION"),
        execution_mode: "local",
        synchronization: "never",
        rule_pack_hash: state.core.rule_pack_hash().to_owned(),
    }
}

#[tauri::command]
fn list_sites(state: State<'_, DesktopState>) -> Vec<SiteSummary> {
    state.core.sites()
}

#[tauri::command]
async fn start_search(
    search_id: String,
    request: SearchRequest,
    on_event: Channel<SearchEvent>,
    state: State<'_, DesktopState>,
) -> Result<SearchCompletion, String> {
    validate_search_id(&search_id)?;
    let cancellation = CancellationToken::new();
    {
        let mut active = state
            .active_searches
            .lock()
            .map_err(|_| "search registry is unavailable".to_owned())?;
        if active.contains_key(&search_id) {
            return Err("search ID is already active".to_owned());
        }
        active.insert(search_id.clone(), cancellation.clone());
    }

    let send_cancellation = cancellation.clone();
    let result = state
        .core
        .run_search(request, cancellation, move |event| {
            if on_event.send(event).is_err() {
                send_cancellation.cancel();
            }
        })
        .await
        .map_err(|error| error.to_string());

    state
        .active_searches
        .lock()
        .map_err(|_| "search registry is unavailable".to_owned())?
        .remove(&search_id);
    result
}

#[tauri::command]
fn cancel_search(search_id: String, state: State<'_, DesktopState>) -> Result<bool, String> {
    validate_search_id(&search_id)?;
    let active = state
        .active_searches
        .lock()
        .map_err(|_| "search registry is unavailable".to_owned())?;
    let Some(cancellation) = active.get(&search_id) else {
        return Ok(false);
    };
    cancellation.cancel();
    Ok(true)
}

fn validate_search_id(search_id: &str) -> Result<(), String> {
    let valid = (8..=128).contains(&search_id.len())
        && search_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
    if valid {
        Ok(())
    } else {
        Err("invalid search ID".to_owned())
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let core = AppCore::from_embedded_rules().expect("embedded Site Rule v1 pack must be valid");
    tauri::Builder::default()
        .manage(DesktopState {
            core: Arc::new(core),
            active_searches: Mutex::new(BTreeMap::new()),
        })
        .invoke_handler(tauri::generate_handler![
            get_app_info,
            list_sites,
            start_search,
            cancel_search
        ])
        .run(tauri::generate_context!())
        .expect("failed to run SocialName desktop");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_ids_are_bounded_and_path_agnostic() {
        assert!(validate_search_id("018ff7a0-demo_search").is_ok());
        assert!(validate_search_id("../escape").is_err());
        assert!(validate_search_id("short").is_err());
    }
}
