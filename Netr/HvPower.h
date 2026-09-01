#ifndef _HV_POWER_H_
#define _HV_POWER_H_

#include <ntddk.h>

NTSTATUS HvPowerInitialize(VOID);
VOID HvPowerCleanup(VOID);
BOOLEAN HvPowerIsInitialized(VOID);

#endif
