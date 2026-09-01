use std::path::PathBuf;
use tauri::State;

use crate::ioctl::codes::*;
use crate::ioctl::DeviceState;
use crate::util::error::{AppError, AppResult};

// Driver.c injection structures are under #pragma pack(push, 1).
const DLL_PATH_WCHARS: usize = 520;
const INJECT_DLL_REQUEST_SIZE: usize = 4 + DLL_PATH_WCHARS * 2 + 3 + 4;
const INJECT_DLL_LEGACY_RESULT_SIZE: usize = 4 + 8 + 4;
const INJECT_DLL_DIAGNOSTICS_SIZE: usize = 4388;
const INJECT_DLL_RESULT_SIZE: usize =
    INJECT_DLL_LEGACY_RESULT_SIZE + INJECT_DLL_DIAGNOSTICS_SIZE;
const INJECT_DLL_USE_MANUAL_MAP_OFFSET: usize = 4 + DLL_PATH_WCHARS * 2 + 2;
const INJECT_DIAGNOSTIC_VERSION: u16 = 1;
const INJECT_DIAGNOSTIC_MAX_EVENTS: usize = 320;
const INJECT_DIAGNOSTIC_SUBJECT_WCHARS: usize = 128;
const INJECT_DIAGNOSTIC_OFFSET: usize = INJECT_DLL_LEGACY_RESULT_SIZE;
const INJECT_DIAGNOSTIC_FAILURE_SUBJECT_OFFSET: usize =
    INJECT_DIAGNOSTIC_OFFSET + 36;
const INJECT_DIAGNOSTIC_CLEANUP_SUBJECT_OFFSET: usize =
    INJECT_DIAGNOSTIC_FAILURE_SUBJECT_OFFSET + INJECT_DIAGNOSTIC_SUBJECT_WCHARS * 2;
const INJECT_DIAGNOSTIC_EVENTS_OFFSET: usize =
    INJECT_DIAGNOSTIC_CLEANUP_SUBJECT_OFFSET + INJECT_DIAGNOSTIC_SUBJECT_WCHARS * 2;
const INJECT_DIAGNOSTIC_EVENT_SIZE: usize = 12;
const STATUS_IMAGE_MACHINE_TYPE_MISMATCH: u32 = 0x4000_000E;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
const STATUS_DYNAMIC_CODE_BLOCKED: u32 = 0xC000_0604;
const SHELLCODE_MAX: usize = 4096;
const INJECT_SHELLCODE_REQUEST_SIZE: usize = 4 + 4 + 8 + 1 + 1 + SHELLCODE_MAX;
const INJECT_SHELLCODE_RESULT_SIZE: usize = 4 + 8;

const _: [(); 1051] = [(); INJECT_DLL_REQUEST_SIZE];
const _: [(); 16] = [(); INJECT_DLL_LEGACY_RESULT_SIZE];
const _: [(); 4388] = [(); INJECT_DLL_DIAGNOSTICS_SIZE];
const _: [(); 4404] = [(); INJECT_DLL_RESULT_SIZE];
const _: [(); 564] = [(); INJECT_DIAGNOSTIC_EVENTS_OFFSET];
const _: [(); 1046] = [(); INJECT_DLL_USE_MANUAL_MAP_OFFSET];
const _: [(); 4114] = [(); INJECT_SHELLCODE_REQUEST_SIZE];
const _: [(); 12] = [(); INJECT_SHELLCODE_RESULT_SIZE];

fn put_u32(buf: &mut [u8], offset: usize, value: u32) {
    buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(buf: &mut [u8], offset: usize, value: u64) {
    buf[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn get_u32(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(buf[offset..offset + 4].try_into().expect("u32 ABI field"))
}

fn get_u16(buf: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(buf[offset..offset + 2].try_into().expect("u16 ABI field"))
}

fn get_u64(buf: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(buf[offset..offset + 8].try_into().expect("u64 ABI field"))
}

#[derive(Debug, Clone)]
struct InjectionDiagnosticEvent {
    stage: u16,
    phase: u16,
    status: u32,
    detail: u32,
}

#[derive(Debug, Clone)]
struct InjectionDiagnostics {
    version: u16,
    size: u16,
    flags: u32,
    primary_stage: u16,
    cleanup_stage: u16,
    primary_status: u32,
    cleanup_status: u32,
    dependency_index: u32,
    dependency_count: u32,
    dropped_event_count: u32,
    failure_subject: String,
    cleanup_subject: String,
    events: Vec<InjectionDiagnosticEvent>,
}

fn get_utf16_string(buf: &[u8], offset: usize, wchar_count: usize) -> String {
    let values: Vec<u16> = (0..wchar_count)
        .map(|index| get_u16(buf, offset + index * 2))
        .take_while(|value| *value != 0)
        .collect();
    String::from_utf16_lossy(&values)
}

fn injection_stage_name(stage: u16) -> &'static str {
    match stage {
        0 => "none",
        1 => "request.validate",
        2 => "manager.initialize",
        3 => "operation.acquire",
        4 => "request.snapshot",
        10 => "file.normalize_path",
        11 => "file.open",
        12 => "file.query",
        13 => "file.validate_size",
        14 => "file.allocate_buffer",
        15 => "file.read",
        16 => "file.validate_dos",
        30 => "manual.validate_input",
        31 => "manual.validate_environment",
        32 => "manual.validate_pe",
        33 => "manual.validate_features",
        34 => "manual.allocate_metadata",
        35 => "manual.build_search_path",
        36 => "manual.allocate_image",
        37 => "manual.attach_process",
        38 => "manual.validate_target",
        39 => "manual.map_sections",
        40 => "manual.relocate",
        41 => "manual.collect_imports",
        42 => "manual.collect_tls",
        43 => "manual.find_ntdll",
        44 => "manual.resolve_dependency_loader",
        45 => "manual.resolve_flush",
        46 => "manual.validate_unwind",
        47 => "manual.resolve_unwind",
        48 => "manual.load_dependencies",
        49 => "manual.reattach_process",
        50 => "manual.validate_process_identity",
        51 => "manual.resolve_imports",
        52 => "manual.protect_image",
        53 => "manual.flush_instruction_cache",
        54 => "manual.register_unwind",
        55 => "manual.attach_tls",
        56 => "manual.call_dllmain",
        57 => "manual.track_module",
        70 => "loader.validate_input",
        71 => "loader.validate_environment",
        72 => "loader.allocate_metadata",
        73 => "loader.normalize_path",
        74 => "loader.build_search_path",
        75 => "loader.attach_process",
        76 => "loader.validate_target",
        77 => "loader.find_ntdll",
        78 => "loader.resolve_routines",
        79 => "loader.allocate_context",
        80 => "loader.write_context",
        81 => "loader.call_ldr_load_dll",
        82 => "loader.read_module_handle",
        83 => "loader.query_image",
        84 => "loader.track_module",
        90 => "dependency.allocate_context",
        91 => "dependency.write_context",
        92 => "dependency.call_loader",
        93 => "dependency.read_module_handle",
        94 => "dependency.free_context",
        110 => "cleanup.dllmain",
        111 => "cleanup.tls",
        112 => "cleanup.unwind",
        113 => "cleanup.dependencies",
        114 => "cleanup.image",
        115 => "cleanup.track_retained",
        116 => "cleanup.loader_unload",
        117 => "cleanup.loader_context",
        200 => "complete",
        _ => "unknown",
    }
}

fn injection_phase_name(phase: u16) -> &'static str {
    match phase {
        1 => "operation",
        2 => "cleanup",
        3 => "warning",
        _ => "unknown",
    }
}

fn stage_has_dependency_detail(stage: u16) -> bool {
    matches!(stage, 90..=94 | 113)
}

fn parse_injection_diagnostics(
    output: &[u8],
    written: usize,
) -> Result<Option<InjectionDiagnostics>, String> {
    if written < INJECT_DLL_RESULT_SIZE {
        return Ok(None);
    }

    let version = get_u16(output, INJECT_DIAGNOSTIC_OFFSET);
    let size = get_u16(output, INJECT_DIAGNOSTIC_OFFSET + 2);
    if version != INJECT_DIAGNOSTIC_VERSION {
        return Err(format!(
            "unsupported injection diagnostic version {version}"
        ));
    }
    if usize::from(size) < INJECT_DLL_DIAGNOSTICS_SIZE {
        return Err(format!(
            "short injection diagnostic payload ({size} bytes)"
        ));
    }

    let event_count = get_u32(output, INJECT_DIAGNOSTIC_OFFSET + 28) as usize;
    let parsed_event_count = event_count.min(INJECT_DIAGNOSTIC_MAX_EVENTS);
    let events = (0..parsed_event_count)
        .map(|index| {
            let offset = INJECT_DIAGNOSTIC_EVENTS_OFFSET
                + index * INJECT_DIAGNOSTIC_EVENT_SIZE;
            InjectionDiagnosticEvent {
                stage: get_u16(output, offset),
                phase: get_u16(output, offset + 2),
                status: get_u32(output, offset + 4),
                detail: get_u32(output, offset + 8),
            }
        })
        .collect();

    Ok(Some(InjectionDiagnostics {
        version,
        size,
        flags: get_u32(output, INJECT_DIAGNOSTIC_OFFSET + 4),
        primary_stage: get_u16(output, INJECT_DIAGNOSTIC_OFFSET + 8),
        cleanup_stage: get_u16(output, INJECT_DIAGNOSTIC_OFFSET + 10),
        primary_status: get_u32(output, INJECT_DIAGNOSTIC_OFFSET + 12),
        cleanup_status: get_u32(output, INJECT_DIAGNOSTIC_OFFSET + 16),
        dependency_index: get_u32(output, INJECT_DIAGNOSTIC_OFFSET + 20),
        dependency_count: get_u32(output, INJECT_DIAGNOSTIC_OFFSET + 24),
        dropped_event_count: get_u32(output, INJECT_DIAGNOSTIC_OFFSET + 32),
        failure_subject: get_utf16_string(
            output,
            INJECT_DIAGNOSTIC_FAILURE_SUBJECT_OFFSET,
            INJECT_DIAGNOSTIC_SUBJECT_WCHARS,
        ),
        cleanup_subject: get_utf16_string(
            output,
            INJECT_DIAGNOSTIC_CLEANUP_SUBJECT_OFFSET,
            INJECT_DIAGNOSTIC_SUBJECT_WCHARS,
        ),
        events,
    }))
}

fn log_injection_diagnostics(
    target_pid: u32,
    manual_map: bool,
    diagnostics: &InjectionDiagnostics,
) {
    let dependency = if diagnostics.dependency_index == u32::MAX {
        "none".to_string()
    } else {
        format!(
            "{}/{}",
            diagnostics.dependency_index.saturating_add(1),
            diagnostics.dependency_count
        )
    };
    let mut lines = Vec::with_capacity(diagnostics.events.len() + 1);
    lines.push(format!(
        "inject.diagnostics target_pid={target_pid} manual_map={manual_map} version={} size={} flags=0x{:08X} primary_stage={} primary_stage_id={} primary_status=0x{:08X} cleanup_stage={} cleanup_stage_id={} cleanup_status=0x{:08X} dependency={} failure_subject={:?} cleanup_subject={:?} events={} dropped_events={} rollback_started={} rollback_unsafe={} mapping_retained={} dependencies_retained={} loader_context_retained={} module_tracked={} process_exited={} cleanup_failed={}",
        diagnostics.version,
        diagnostics.size,
        diagnostics.flags,
        injection_stage_name(diagnostics.primary_stage),
        diagnostics.primary_stage,
        diagnostics.primary_status,
        injection_stage_name(diagnostics.cleanup_stage),
        diagnostics.cleanup_stage,
        diagnostics.cleanup_status,
        dependency,
        diagnostics.failure_subject,
        diagnostics.cleanup_subject,
        diagnostics.events.len(),
        diagnostics.dropped_event_count,
        diagnostics.flags & 0x0000_0004 != 0,
        diagnostics.flags & 0x0000_0008 != 0,
        diagnostics.flags & 0x0000_0010 != 0,
        diagnostics.flags & 0x0000_0020 != 0,
        diagnostics.flags & 0x0000_0040 != 0,
        diagnostics.flags & 0x0000_0080 != 0,
        diagnostics.flags & 0x0000_0200 != 0,
        diagnostics.flags & 0x0000_0400 != 0,
    ));

    for (sequence, event) in diagnostics.events.iter().enumerate() {
        let record_type = match event.phase {
            2 => "inject.cleanup",
            3 => "inject.warning",
            _ => "inject.stage",
        };
        let dependency_detail = if event.stage == 113 {
            format!(
                " dependency_index={}",
                event.detail.saturating_add(1)
            )
        } else if stage_has_dependency_detail(event.stage) {
            format!(
                " dependency_index={} search={}",
                (event.detail & 0x7FFF_FFFF).saturating_add(1),
                if event.detail & 0x8000_0000 != 0 {
                    "default"
                } else {
                    "dll_directory"
                }
            )
        } else {
            String::new()
        };
        lines.push(format!(
            "{record_type} target_pid={target_pid} sequence={} phase={} stage={} stage_id={} ntstatus=0x{:08X} detail=0x{:08X}{dependency_detail}",
            sequence + 1,
            injection_phase_name(event.phase),
            injection_stage_name(event.stage),
            event.stage,
            event.status,
            event.detail,
        ));
    }
    super::debugger_bridge::injection_diag_lines(&lines);
}

fn injection_diagnostic_context(diagnostics: &InjectionDiagnostics) -> String {
    let mut context = format!(
        "stage={} ({}), stage_status=0x{:08X}",
        injection_stage_name(diagnostics.primary_stage),
        diagnostics.primary_stage,
        diagnostics.primary_status
    );
    if !diagnostics.failure_subject.is_empty() {
        context.push_str(&format!(
            ", dependency={:?}",
            diagnostics.failure_subject
        ));
    }
    if diagnostics.cleanup_stage != 0 {
        context.push_str(&format!(
            ", cleanup_stage={} ({}), cleanup_status=0x{:08X}",
            injection_stage_name(diagnostics.cleanup_stage),
            diagnostics.cleanup_stage,
            diagnostics.cleanup_status
        ));
    }
    context
}

fn inject_status_detail(status: u32, manual_map: bool) -> &'static str {
    match status {
        0xC000_0022 => "access denied",
        0xC000_0034 => "DLL file was not found",
        0xC000_003A => "DLL path was not found",
        0xC000_007B => "invalid or incompatible PE image",
        STATUS_IMAGE_MACHINE_TYPE_MISMATCH if manual_map => {
            "VT manual-map currently supports native x64 targets only"
        }
        STATUS_IMAGE_MACHINE_TYPE_MISMATCH => {
            "the kernel loader transport cannot service this target architecture"
        }
        STATUS_NOT_SUPPORTED => "this kernel or image configuration is not supported",
        STATUS_DYNAMIC_CODE_BLOCKED if manual_map => {
            "the target process prohibits private executable memory; VT manual-map cannot preserve its current semantics under this mitigation"
        }
        STATUS_DYNAMIC_CODE_BLOCKED => {
            "the target process prohibits the kernel loader call stub; use the image-backed Windows loader transport"
        }
        0xC000_0135 if manual_map => {
            "the target loader could not resolve a direct or transitive dependency from the DLL directory or the target process search path"
        }
        0xC000_0135 => "Windows loader could not find the DLL or one of its dependencies",
        0xC000_0139 => "an imported procedure was not found",
        0xC000_0142 => "DllMain returned failure",
        _ => "see the NTSTATUS value for the failing stage",
    }
}

fn injection_failure(
    target_pid: u32,
    stage: &str,
    message: impl Into<String>,
    initial_log: Option<&PathBuf>,
) -> AppError {
    let message = message.into();
    let log_path = super::debugger_bridge::injection_diag(format!(
        "inject.failure target_pid={target_pid} stage={stage} error={message}"
    ))
    .or_else(|| initial_log.cloned());
    let diagnostic = log_path
        .map(|path| format!("; diagnostic log: {}", path.display()))
        .unwrap_or_else(|| "; diagnostic log could not be written".into());
    AppError::Internal(format!("{message}{diagnostic}"))
}

fn resolve_dll_path(dll_path: Option<String>, dll_bytes: Option<Vec<u8>>) -> AppResult<String> {
    if let Some(path) = dll_path.filter(|value| !value.trim().is_empty()) {
        return Ok(path);
    }

    // Compatibility with the old command argument: callers may pass a UTF-8
    // encoded path in dllBytes. Actual DLL image bytes are not this IOCTL's ABI.
    if let Some(bytes) = dll_bytes.filter(|value| !value.is_empty()) {
        return String::from_utf8(bytes).map_err(|_| {
            AppError::Internal(
                "inject_dll expects a DLL path; raw DLL image bytes are not supported by the driver IOCTL"
                    .into(),
            )
        });
    }

    Err(AppError::Internal("DLL path must not be empty".into()))
}

#[tauri::command]
pub fn inject_dll(
    device: State<'_, DeviceState>,
    pid: u32,
    dll_path: Option<String>,
    dll_bytes: Option<Vec<u8>>,
    manual_map: Option<bool>,
) -> AppResult<()> {
    if pid == 0 {
        return Err(AppError::Internal("target PID must be non-zero".into()));
    }
    let path = resolve_dll_path(dll_path, dll_bytes)?;
    let manual_map = manual_map.unwrap_or(false);
    let initial_log = super::debugger_bridge::injection_diag(format!(
        "inject.request target_pid={pid} manual_map={manual_map} dll={path}"
    ));
    let wide: Vec<u16> = path.encode_utf16().collect();
    if wide.len() >= DLL_PATH_WCHARS {
        return Err(injection_failure(
            pid,
            "validate.path",
            format!(
                "DLL path is too long ({} UTF-16 code units; max {})",
                wide.len(),
                DLL_PATH_WCHARS - 1
            ),
            initial_log.as_ref(),
        ));
    }

    let mut request = vec![0u8; INJECT_DLL_REQUEST_SIZE];
    put_u32(&mut request, 0, pid);
    for (index, value) in wide.iter().enumerate() {
        let offset = 4 + index * 2;
        request[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
    request[INJECT_DLL_USE_MANUAL_MAP_OFFSET] = u8::from(manual_map);

    let mut output = vec![0u8; INJECT_DLL_RESULT_SIZE];
    let written = match device.ioctl(IOCTL_HV_INJECT_DLL, &request, &mut output) {
        Ok(written) => written as usize,
        Err(error) => {
            super::debugger_bridge::injection_diag(format!(
                "inject.ioctl.failure target_pid={pid} manual_map={manual_map} error={error}"
            ));
            return Err(injection_failure(
                pid,
                "ioctl",
                error.to_string(),
                initial_log.as_ref(),
            ));
        }
    };
    if written < INJECT_DLL_LEGACY_RESULT_SIZE {
        super::debugger_bridge::injection_diag(format!(
            "inject.ioctl.short target_pid={pid} bytes={written}"
        ));
        return Err(injection_failure(
            pid,
            "ioctl.short",
            format!("INJECT_DLL returned a short result ({written} bytes)"),
            initial_log.as_ref(),
        ));
    }
    let status = get_u32(&output, 0);
    let module_base = get_u64(&output, 4);
    let module_size = get_u32(&output, 12);
    super::debugger_bridge::injection_diag(format!(
        "inject.ioctl.result target_pid={pid} bytes={written} ntstatus=0x{status:08X} module_base=0x{module_base:X} module_size=0x{module_size:X}"
    ));
    let diagnostics = match parse_injection_diagnostics(&output, written) {
        Ok(Some(diagnostics)) => {
            log_injection_diagnostics(pid, manual_map, &diagnostics);
            Some(diagnostics)
        }
        Ok(None) => {
            super::debugger_bridge::injection_diag(format!(
                "inject.diagnostics.unavailable target_pid={pid} bytes={written} legacy_result_size={INJECT_DLL_LEGACY_RESULT_SIZE} expected_result_size={INJECT_DLL_RESULT_SIZE}"
            ));
            None
        }
        Err(error) => {
            super::debugger_bridge::injection_diag(format!(
                "inject.diagnostics.invalid target_pid={pid} bytes={written} error={error}"
            ));
            None
        }
    };
    if status != 0 {
        if !manual_map
            && matches!(
                status,
                STATUS_NOT_SUPPORTED
                    | STATUS_DYNAMIC_CODE_BLOCKED
                    | STATUS_IMAGE_MACHINE_TYPE_MISMATCH
            )
        {
            return super::debugger_bridge::inject_dll_via_windows_loader(pid, &path)
                .map_err(|error| {
                    AppError::Internal(format!(
                        "INJECT_DLL kernel transport is unavailable (NTSTATUS=0x{status:08X}: {}); Windows loader transport also failed: {error}",
                        inject_status_detail(status, manual_map)
                    ))
                });
        }
        let diagnostic_context = diagnostics
            .as_ref()
            .map(|value| format!("; {}", injection_diagnostic_context(value)))
            .unwrap_or_default();
        return Err(injection_failure(
            pid,
            "kernel.result",
            format!(
                "INJECT_DLL failed: NTSTATUS=0x{status:08X}: {}{diagnostic_context}",
                inject_status_detail(status, manual_map),
            ),
            initial_log.as_ref(),
        ));
    }
    super::debugger_bridge::injection_diag(format!(
        "inject.success target_pid={pid} transport=kernel manual_map={manual_map}"
    ));
    Ok(())
}

#[tauri::command]
pub fn inject_shellcode(
    device: State<'_, DeviceState>,
    pid: u32,
    shellcode: Vec<u8>,
) -> AppResult<()> {
    if pid == 0 {
        return Err(AppError::Internal("target PID must be non-zero".into()));
    }
    if shellcode.is_empty() || shellcode.len() > SHELLCODE_MAX {
        return Err(AppError::Internal(format!(
            "shellcode size must be 1..={SHELLCODE_MAX} bytes"
        )));
    }

    let mut request = vec![0u8; INJECT_SHELLCODE_REQUEST_SIZE];
    put_u32(&mut request, 0, pid);
    put_u32(&mut request, 4, shellcode.len() as u32);
    put_u64(&mut request, 8, 0); // Parameter
    request[16] = 1; // ExecuteImmediately
    request[17] = 0; // HideMemory
    request[18..18 + shellcode.len()].copy_from_slice(&shellcode);

    let mut output = [0u8; INJECT_SHELLCODE_RESULT_SIZE];
    let written = device.ioctl(IOCTL_HV_INJECT_SHELLCODE, &request, &mut output)? as usize;
    if written < INJECT_SHELLCODE_RESULT_SIZE {
        return Err(AppError::Internal(format!(
            "INJECT_SHELLCODE returned a short result ({written} bytes)"
        )));
    }
    let status = get_u32(&output, 0);
    if status != 0 {
        return Err(AppError::Internal(format!(
            "INJECT_SHELLCODE failed: driver status={status}"
        )));
    }
    Ok(())
}
