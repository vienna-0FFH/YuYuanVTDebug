#include "HvPower.h"
#include "HvCore.h"
#include "HvInput.h"
#include "HvUsbXhci.h"

/* These WDM GUIDs are declared by the headers but not emitted by this
 * driver project (it intentionally does not define INITGUID globally). */
const GUID GUID_MONITOR_POWER_ON =
    { 0x02731015, 0x4510, 0x4526,
      { 0x99, 0xE6, 0xE5, 0xA1, 0x7E, 0xBD, 0x1A, 0xEA } };
const GUID GUID_CONSOLE_DISPLAY_STATE =
    { 0x6FE69556, 0x704A, 0x47A0,
      { 0x8F, 0x24, 0xC2, 0x8D, 0x93, 0x6F, 0xDA, 0x47 } };
const GUID GUID_LIDSWITCH_STATE_CHANGE =
    { 0xBA3E0F4D, 0xB817, 0x4094,
      { 0xA2, 0xD1, 0xD5, 0x63, 0x79, 0xE6, 0xA0, 0xF3 } };

typedef struct _HV_POWER_CONTEXT {
    PVOID ConsoleDisplayHandle;
    PVOID MonitorHandle;
    PVOID LidHandle;
    volatile LONG Initialized;
} HV_POWER_CONTEXT;

static HV_POWER_CONTEXT g_HvPower = { 0 };
static volatile LONG g_HvPowerOfflineMarker = FALSE;

static VOID
HvPowerEnterOffline(_In_ PCSTR Reason)
{
    if (InterlockedExchange(&g_HvPowerOfflineMarker, TRUE) != FALSE) {
        return;
    }

    DbgPrint("[HV-POWER] entering offline state (%s); reload required after resume\n",
             Reason ? Reason : "power transition");
    HvMarkPowerOffline();
    HvInputBeginShutdown();
    HvUsbXhciBeginShutdown();
}

static NTSTATUS
HvPowerSettingCallback(
    _In_ LPCGUID SettingGuid,
    _In_reads_bytes_(ValueLength) PVOID Value,
    _In_ ULONG ValueLength,
    _Inout_opt_ PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);

    /* Registration may synchronously deliver an initial notification without
     * a materialized value.  A notification callback must ignore that state;
     * returning STATUS_INVALID_PARAMETER makes registration itself fail. */
    if (!SettingGuid || !Value || ValueLength == 0) {
        return STATUS_SUCCESS;
    }

    if (IsEqualGUID(SettingGuid, &GUID_CONSOLE_DISPLAY_STATE) &&
        ValueLength >= sizeof(MONITOR_DISPLAY_STATE)) {
        MONITOR_DISPLAY_STATE state = *(PMONITOR_DISPLAY_STATE)Value;
        if (state == PowerMonitorOff) {
            HvPowerEnterOffline("console display off");
        } else if (state == PowerMonitorOn) {
            DbgPrint("[HV-POWER] display resumed; VT remains offline until driver reload\n");
        }
        return STATUS_SUCCESS;
    }

    if (IsEqualGUID(SettingGuid, &GUID_MONITOR_POWER_ON) &&
        ValueLength >= sizeof(ULONG)) {
        if (*(PULONG)Value == 0) {
            HvPowerEnterOffline("monitor power off");
        }
        return STATUS_SUCCESS;
    }

    if (IsEqualGUID(SettingGuid, &GUID_LIDSWITCH_STATE_CHANGE) &&
        ValueLength >= sizeof(BOOLEAN)) {
        if (!*(PBOOLEAN)Value) {
            HvPowerEnterOffline("lid closed");
        }
        return STATUS_SUCCESS;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
HvPowerInitialize(VOID)
{
    NTSTATUS status;

    if (InterlockedCompareExchange(&g_HvPower.Initialized, 0, 0) != 0) {
        return STATUS_ALREADY_INITIALIZED;
    }

    RtlZeroMemory(&g_HvPower, sizeof(g_HvPower));
    InterlockedExchange(&g_HvPowerOfflineMarker, FALSE);

    /* This is a legacy non-PnP software driver, so callbacks are global and
     * are not associated with its control device object. */
    status = PoRegisterPowerSettingCallback(
        NULL,
        &GUID_CONSOLE_DISPLAY_STATE,
        HvPowerSettingCallback,
        NULL,
        &g_HvPower.ConsoleDisplayHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[HV-POWER] console display callback registration failed: 0x%X\n",
                 status);
        RtlZeroMemory(&g_HvPower, sizeof(g_HvPower));
        return status;
    }

    status = PoRegisterPowerSettingCallback(
        NULL,
        &GUID_MONITOR_POWER_ON,
        HvPowerSettingCallback,
        NULL,
        &g_HvPower.MonitorHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[HV-POWER] monitor callback unavailable: 0x%X\n", status);
        g_HvPower.MonitorHandle = NULL;
    }

    status = PoRegisterPowerSettingCallback(
        NULL,
        &GUID_LIDSWITCH_STATE_CHANGE,
        HvPowerSettingCallback,
        NULL,
        &g_HvPower.LidHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[HV-POWER] lid callback unavailable: 0x%X\n", status);
        g_HvPower.LidHandle = NULL;
    }

    InterlockedExchange(&g_HvPower.Initialized, TRUE);
    DbgPrint("[HV-POWER] global power setting callbacks registered\n");
    return STATUS_SUCCESS;
}

VOID
HvPowerCleanup(VOID)
{
    /* No new VT or input operation may start while callback ownership is
     * being removed during unload. */
    HvMarkPowerOffline();

    if (InterlockedExchange(&g_HvPower.Initialized, FALSE) == FALSE) {
        return;
    }

    if (g_HvPower.LidHandle) {
        PoUnregisterPowerSettingCallback(g_HvPower.LidHandle);
    }
    if (g_HvPower.MonitorHandle) {
        PoUnregisterPowerSettingCallback(g_HvPower.MonitorHandle);
    }
    if (g_HvPower.ConsoleDisplayHandle) {
        PoUnregisterPowerSettingCallback(g_HvPower.ConsoleDisplayHandle);
    }

    RtlZeroMemory(&g_HvPower, sizeof(g_HvPower));
}

BOOLEAN
HvPowerIsInitialized(VOID)
{
    return InterlockedCompareExchange(&g_HvPower.Initialized, 0, 0) != 0;
}
