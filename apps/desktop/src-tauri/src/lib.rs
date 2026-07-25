#![forbid(unsafe_code)]

use std::{
    collections::BTreeMap,
    fs,
    sync::{Arc, Mutex},
};

use serde::Serialize;
use socialname_app_core::{
    AppCore, SearchCompletion, SearchEvent, SearchPolicy, SearchRequest, SearchSource, SiteSummary,
    SyncPolicy,
};
use socialname_cache::LocalCache;
use tauri::{Manager, State, ipc::Channel};
use tokio_util::sync::CancellationToken;

struct DesktopState {
    core: Arc<AppCore>,
    cache_error: Option<String>,
    active_searches: Mutex<BTreeMap<String, CancellationToken>>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AppInfo {
    version: &'static str,
    available_sources: [SearchSource; 2],
    default_policy: SearchPolicy,
    synchronization: SyncPolicy,
    cache_ready: bool,
    cache_error: Option<String>,
    rule_pack_hash: String,
}

#[tauri::command]
fn get_app_info(state: State<'_, DesktopState>) -> AppInfo {
    AppInfo {
        version: env!("CARGO_PKG_VERSION"),
        available_sources: [SearchSource::Local, SearchSource::Cache],
        default_policy: SearchPolicy::default(),
        synchronization: SyncPolicy::Never,
        cache_ready: state.cache_error.is_none(),
        cache_error: state.cache_error.clone(),
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
    tauri::Builder::default()
        .setup(|app| {
            let core =
                AppCore::from_embedded_rules().expect("embedded Site Rule v1 pack must be valid");
            let cache_result = app
                .path()
                .app_local_data_dir()
                .map_err(|error| error.to_string())
                .and_then(|directory| {
                    fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
                    tauri::async_runtime::block_on(LocalCache::open(
                        directory.join("observations.sqlite3"),
                    ))
                    .map_err(|error| error.to_string())
                });
            let (core, cache_error) = match cache_result {
                Ok(cache) => (core.with_local_cache(cache), None),
                Err(error) => (core, Some(error)),
            };
            app.manage(DesktopState {
                core: Arc::new(core),
                cache_error,
                active_searches: Mutex::new(BTreeMap::new()),
            });
            Ok(())
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
