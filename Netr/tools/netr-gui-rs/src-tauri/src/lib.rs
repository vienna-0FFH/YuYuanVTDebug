mod commands;
mod dbgevt;
mod ioctl;
mod license;
mod util;

use std::sync::Arc;

use commands::ai_session::AiSessionStore;
use commands::annotations::AnnotationStore;
use commands::debugger_ui::{DebuggerHandles, FreezeStore};
use commands::mcp_client::McpRegistry;
use commands::sig_store::SignatureStore;
use commands::symbol::SymbolStore;
use ioctl::DeviceState;
use license::AuthState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_shell::init())
        .manage(AuthState::new())
        .manage(DeviceState::new())
        .manage(Arc::new(DebuggerHandles::default()))
        .manage(Arc::new(FreezeStore::default()))
        .manage(SymbolStore::default())
        .manage(Arc::new(AiSessionStore::new()))
        .manage(Arc::new(AnnotationStore::new()))
        .manage(Arc::new(McpRegistry::new()))
        .manage({
            // 启动时从 %LOCALAPPDATA% 全局库加载已保存签名
            let s = Arc::new(SignatureStore::new());
            s.replace(commands::sig_store::load_library());
            s
        })
        .invoke_handler(tauri::generate_handler![
            // auth
            commands::auth::auth_bootstrap,
            commands::auth::auth_login,
            commands::auth::auth_auto_login,
            commands::auth::auth_logout,
            commands::auth::auth_heartbeat,
            commands::auth::auth_is_authorized,
            commands::auth::auth_register,
            commands::auth::auth_change_password,
            commands::auth::auth_topup,
            // license
            commands::license::license_submit_to_driver,
            commands::license::license_dump,
            // driver / service
            commands::driver::driver_install,
            commands::driver::driver_start,
            commands::driver::driver_stop,
            commands::driver::driver_uninstall,
            commands::driver::driver_query,
            commands::driver::driver_open_device,
            commands::driver::driver_close_device,
            commands::driver::driver_device_open,
            commands::driver::driver_get_status,
            // dse
            commands::dse::dse_status,
            commands::dse::dse_enable,
            commands::dse::dse_disable,
            // hide
            commands::hide::hide_process,
            commands::hide::unhide_process,
            commands::hide::hide_driver,
            commands::hide::unhide_driver,
            // debugger
            commands::debugger::debugger_add,
            commands::debugger::debugger_remove,
            commands::antivmp::antivmp_get_status,
            commands::antivmp::antivmp_apply,
            commands::antivmp::antivmp_set_private_debug_object,
            commands::debugger_ui::dbg_symbol_cache_get,
            commands::debugger_ui::dbg_symbol_cache_set,
            commands::debugger_bridge::debugger_bridge_launch,
            commands::debugger_bridge::debugger_bridge_inject,
            // hwbp
            commands::hwbp::hwbp_set,
            commands::hwbp::hwbp_clear,
            commands::hwbp::hwbp_list,
            // memory
            commands::memory::memory_read,
            commands::memory::memory_write,
            commands::memory::memory_alloc,
            commands::memory::memory_free,
            // inject
            commands::inject::inject_dll,
            commands::inject::inject_shellcode,
            // input
            commands::input::input_enable,
            commands::input::input_disable,
            commands::input::input_send_key,
            commands::input::input_send_mouse,
            // system
            commands::system::system_list_processes,
            commands::system::system_launch_process,
            commands::system::system_process_alive,
            commands::system::system_resolve_driver_path,
            commands::system::system_is_elevated,
            commands::system::system_restart_as_admin,
            // debugger UI 完整套
            commands::debugger_ui::dbg_open_window,
            commands::debugger_ui::dbg_close_window,
            commands::debugger_ui::trace_open_window,
            commands::debugger_ui::dbg_attach,
            commands::debugger_ui::dbg_detach,
            commands::debugger_ui::dbg_launch_executable,
            commands::debugger_ui::dbg_restart_process,
            commands::debugger_ui::dbg_run_to_entry,
            commands::debugger_ui::dbg_read_memory,
            commands::debugger_ui::dbg_write_memory,
            commands::debugger_ui::dbg_disasm,
            commands::debugger_ui::dbg_list_modules,
            commands::debugger_ui::dbg_list_threads,
            commands::debugger_ui::dbg_list_regions,
            commands::debugger_ui::dbg_get_thread_context,
            commands::debugger_ui::dbg_set_thread_context,
            commands::debugger_ui::dbg_suspend_thread,
            commands::debugger_ui::dbg_resume_thread,
            commands::debugger_ui::dbg_sw_bp_set,
            commands::debugger_ui::dbg_sw_bp_clear,
            commands::debugger_ui::dbg_sw_bp_list,
            commands::debugger_ui::dbg_scan_first,
            commands::debugger_ui::dbg_scan_next,
            commands::debugger_ui::dbg_scan_reset,
            commands::debugger_ui::dbg_scan_cancel,
            commands::debugger_ui::dbg_scan_refresh,
            commands::access_watch::dbg_find_who_accesses,
            commands::debugger_ui::dbg_self_pid,
            commands::debugger_ui::dbg_self_protected,
            commands::debugger_ui::dbg_set_self_protected,
              commands::debugger_ui::dbg_step_into,
              commands::debugger_ui::dbg_step_over,
              commands::debugger_ui::dbg_step_many,
              commands::debugger_ui::dbg_step_out,
              commands::debugger_ui::dbg_cancel_active_run,
            commands::debugger_ui::dbg_consume_transient_bp,
            commands::debugger_ui::dbg_freeze_set,
            commands::debugger_ui::dbg_freeze_clear,
            commands::debugger_ui::dbg_freeze_list,
            commands::symbol::dbg_resolve_symbol,
            commands::symbol::dbg_resolve_symbols,
            commands::dissect::dbg_dissect,
            commands::ptr_scan::dbg_ptr_scan,
            commands::lua_engine::dbg_lua_run,
            commands::assembler::dbg_assemble_patch,
            commands::aob_scan::dbg_aob_scan,
            commands::find_globals::dbg_find_globals,
            commands::dump::dbg_dump_region,
            commands::dump::dbg_dump_module,
            commands::dump::dbg_dump_process,
            // P99 签名管理
            commands::sig_store::sig_list,
            commands::sig_store::sig_save,
            commands::sig_store::sig_delete,
            commands::sig_store::sig_snapshot,
            commands::sig_store::sig_replace,
            commands::sig_discover::sig_test,
            commands::sig_discover::sig_derive,
            commands::sig_discover::sig_validate,
            commands::sig_discover::sig_quick_test,
            commands::sig_discover::sig_main_exe,
            commands::llm::dbg_llm_call,
            commands::ai_chat::dbg_ai_chat,
            commands::ai_chat::dbg_ai_run,
            commands::ai_chat::dbg_ai_cancel,
            commands::ai_chat::dbg_ai_session_list,
            commands::ai_chat::dbg_ai_session_load,
            commands::ai_chat::dbg_ai_session_delete,
            commands::ai_chat::dbg_ai_tools_describe,
            commands::ai_config::ai_config_load,
            commands::ai_config::ai_config_save,
            commands::ai_config::ai_config_clear,
            commands::fs_tools::ai_read_dropped_file,
            // P88 项目保存/加载
            commands::project_io::project_save,
            commands::project_io::project_load,
            commands::project_io::project_new,
            commands::project_io::project_list_recent,
            commands::project_io::project_pick_save,
            commands::project_io::project_pick_open,
            // P91-P94 逆向工具
            commands::xref::dbg_xref_to,
            commands::xref::dbg_xref_from,
            commands::functions::dbg_list_functions,
            commands::functions::dbg_get_function,
            commands::pe_strings::dbg_list_strings,
            commands::pe_imports::dbg_list_imports,
            commands::pe_imports::dbg_list_exports,
            commands::call_stack::dbg_call_stack,
            commands::annotations::anno_set_label,
            commands::annotations::anno_get_label,
            commands::annotations::anno_set_comment,
            commands::annotations::anno_get_comment,
            commands::annotations::anno_define_function,
            commands::annotations::anno_get_function,
            commands::annotations::anno_snapshot,
            commands::annotations::anno_replace,
            commands::annotations::anno_list_labels,
            // P115 MCP client (IDA / Ghidra / Filesystem / GitHub 等)
            commands::mcp_client::mcp_list_servers,
            commands::mcp_client::mcp_get_configs,
            commands::mcp_client::mcp_upsert_server,
            commands::mcp_client::mcp_remove_server,
            commands::mcp_client::mcp_connect,
            commands::mcp_client::mcp_disconnect,
            commands::mcp_client::mcp_list_tools,
            commands::mcp_client::mcp_call_tool,
        ])
        .setup(|app| {
            // Phase 6: 启动 dbgevt 1Hz 后台轮询
            dbgevt::poller::spawn(app.handle().clone());

            // P15: freeze writer 10Hz
            {
                use tauri::Manager;
                let handles = app.state::<Arc<DebuggerHandles>>().inner().clone();
                let freeze = app.state::<Arc<FreezeStore>>().inner().clone();
                commands::debugger_ui::spawn_freeze_writer(
                    app.handle().clone(),
                    handles.clone(),
                    freeze,
                );
                commands::debugger_ui::spawn_private_event_poller(
                    app.handle().clone(),
                    handles,
                );
            }

            #[cfg(debug_assertions)]
            {
                use tauri::Manager;
                if let Some(win) = app.get_webview_window("main") {
                    win.open_devtools();
                }
            }
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app, event| {
            // 进程退出前向 driver 注销自身 + 关 device。driver 的
            // PsSetCreateProcessNotifyRoutineEx 回调本来也会兜底,但走显式 IOCTL
            // 更早一拍 (loader 还在,IOCTL 路径稳),省得 PID 复用带来的窗口期。
            if matches!(event, tauri::RunEvent::ExitRequested { .. } | tauri::RunEvent::Exit) {
                use tauri::Manager;
                let device = app.state::<DeviceState>();
                let handles = app.state::<Arc<DebuggerHandles>>().inner().clone();
                let freeze = app.state::<Arc<FreezeStore>>().inner().clone();
                let _ = commands::debugger_ui::cleanup_all_builtin_targets(
                    &handles,
                    device.inner(),
                    &freeze,
                );
                let pid = std::process::id();
                let _ = commands::debugger::debugger_remove(device.clone(), pid);
                device.close();
            }
        });
}
