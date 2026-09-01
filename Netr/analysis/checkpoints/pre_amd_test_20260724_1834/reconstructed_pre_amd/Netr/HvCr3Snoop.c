/*
 * HvCr3Snoop.c —— 见 HvCr3Snoop.h 注释
 */

#include "HvCr3Snoop.h"
#include <intrin.h>

// P122: 全 driver DbgPrint → GUI ring
#define HV_TRACE_THIS_CAT HV_TRACE_CAT_UTIL
#include "HvTrace.h"

// CR3 低 12 位是 PCID/flags,Mask 后是 page-aligned 物理基址
#define CR3_PFN_MASK    0x000FFFFFFFFFF000ULL

static volatile UINT64 g_Cr3Ring[HV_CR3_SNOOP_RING_SIZE];
static volatile LONG   g_Cr3RingIdx = 0;
static volatile LONG   g_SnoopEnabled = 0;

// User canonical 上限 (47-bit user half: 0x0000_0000_0000_0000 ~ 0x0000_7FFF_FFFF_FFFF)
#define USER_VA_LIMIT  0x0000800000000000ULL

VOID HvCr3SnoopRecord(_In_ UINT64 GuestCr3, _In_ UINT64 GuestRip)
{
    if (g_SnoopEnabled == 0) return;

    UINT64 cr3 = GuestCr3 & CR3_PFN_MASK;
    if (cr3 == 0) return;

    // **关键过滤**: 只在 GuestRip 处于 user 半空间时记录。
    // KVAS 启用的 Win10 22H2 / Win11 上, kernel-mode VMEXIT (EPT / IO / Ext.Intr
    // / VMCALL) 的 GUEST_CR3 是 shadow CR3, 其 PML4 user-half (entry 0..255)
    // 几乎全空, 对 user GVA walk 必败。User-mode VMEXIT (#PF 触发的 EPT,
    // CPUID, INVLPG 等) 才看到真 user CR3。
    //
    // GuestRip == 0 → 兼容入口, 不过滤直接记录(用于早期未带 RIP 的调用)。
    if (GuestRip != 0 && GuestRip >= USER_VA_LIMIT) {
        return;  // kernel-mode RIP → 大概率 shadow CR3, 丢弃
    }

    // 简单去重:跟最近写入的 slot 比一下,相同则跳过
    LONG idx = g_Cr3RingIdx;
    LONG prevIdx = (idx - 1) & (HV_CR3_SNOOP_RING_SIZE - 1);
    if (g_Cr3Ring[prevIdx] == cr3) {
        return;
    }

    // 拿下一个 slot 并写入。InterlockedIncrement 保证多核不会写到同一 slot
    LONG newIdx = InterlockedIncrement(&g_Cr3RingIdx);
    g_Cr3Ring[(newIdx - 1) & (HV_CR3_SNOOP_RING_SIZE - 1)] = cr3;
}

ULONG HvCr3SnoopSnapshot(
    _Out_writes_to_(MaxCount, return) UINT64* OutBuffer,
    _In_ ULONG MaxCount)
{
    if (!OutBuffer || MaxCount == 0) return 0;

    ULONG cap = (MaxCount < HV_CR3_SNOOP_RING_SIZE) ? MaxCount : HV_CR3_SNOOP_RING_SIZE;
    ULONG outCount = 0;

    for (ULONG i = 0; i < HV_CR3_SNOOP_RING_SIZE && outCount < cap; i++) {
        UINT64 v = g_Cr3Ring[i];
        if (v == 0) continue;

        // 去重:O(n^2) 但 n=64,可接受
        BOOLEAN dup = FALSE;
        for (ULONG j = 0; j < outCount; j++) {
            if (OutBuffer[j] == v) { dup = TRUE; break; }
        }
        if (!dup) {
            OutBuffer[outCount++] = v;
        }
    }

    return outCount;
}

VOID HvCr3SnoopEnable(VOID)
{
    InterlockedExchange(&g_SnoopEnabled, 1);
}

VOID HvCr3SnoopDisable(VOID)
{
    InterlockedExchange(&g_SnoopEnabled, 0);
}

BOOLEAN HvCr3SnoopIsEnabled(VOID)
{
    return g_SnoopEnabled != 0;
}
