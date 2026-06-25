/*
 * HvTrace.h — P122 driver-wide DbgPrint → GUI ring 总线
 *
 * 设计:
 *   1) #define DbgPrint(...) HvTracePrint(...) 重定向.
 *      HvTracePrint 内部:
 *        - vsnprintf 出消息
 *        - vDbgPrintExWithPrefix 走 WinDbg (绕过宏定义, 老行为保留)
 *        - HvDbgEvtPost 写 ring
 *
 *   2) 不走 DbgPrint 函数自身 — 因为我们 #define 了 DbgPrint, 在 HvTracePrint 内部
 *      再调 DbgPrint 会递归. 用 ntoskrnl 暴露的 vDbgPrintExWithPrefix (更底层 API)
 *      直接打 KD, 避开宏.
 *
 *   3) Category 默认 HV_TRACE_CAT_GENERIC. 每个 .c 文件在 include 前可 #define
 *      HV_TRACE_THIS_CAT HV_TRACE_CAT_XXX 覆盖归类.
 *
 *   4) Severity 启发式从消息内容推: ERROR/FAIL → ERROR, WARN → WARN, 其余 INFO.
 *
 *   5) IRQL: vDbgPrintExWithPrefix 任意 IRQL OK; HvDbgEvtPost 内部 spinlock, <=DISPATCH OK.
 *
 *   6) 关闭: 编译 #define HV_TRACE_DISABLE 1 跳过, 回到纯 DbgPrint.
 *
 * 使用:
 *   - 全 driver .c 在 #include "HvHook.h" 之后任意位置 include 这个头.
 *   - 想显式归类: include 之前 `#define HV_TRACE_THIS_CAT HV_TRACE_CAT_VM`.
 */

#ifndef _HV_TRACE_H_
#define _HV_TRACE_H_

#pragma once

#include "HvHook.h"   // HV_TRACE_CAT_* / HV_DBGEVT_SEV_* / HvDbgEvtPost

#ifndef HV_TRACE_DISABLE
#define HV_TRACE_DISABLE 0
#endif

#if !HV_TRACE_DISABLE

#include <stdarg.h>
#include <ntstrsafe.h>   // RtlStringCbVPrintfA — 替代 _vsnprintf 避免链接重定义

// ntoskrnl 直接暴露的 v 系列 API — 不被我们的 DbgPrint 宏污染.
// vDbgPrintExWithPrefix 任意 IRQL OK, 行为 = DbgPrint("[prefix]" fmt, args)
NTSYSAPI ULONG NTAPI vDbgPrintExWithPrefix(
    _In_z_ PCSTR Prefix,
    _In_ ULONG ComponentId,
    _In_ ULONG Level,
    _In_z_ _Printf_format_string_ PCSTR Format,
    _In_ va_list arglist);

// 默认 cat
#ifndef HV_TRACE_THIS_CAT
#define HV_TRACE_THIS_CAT  HV_TRACE_CAT_GENERIC
#endif

// 启发式判 severity — 扫前 64 字节找 ERROR/FAIL/WARN
__forceinline ULONG HvTracepSeverityFromMsg(_In_z_ const char* msg)
{
    for (int i = 0; i < 64 && msg[i]; i++) {
        char c0 = msg[i];
        if (i + 3 >= 64) break;
        char c1 = msg[i+1]; if (!c1) break;
        char c2 = msg[i+2]; if (!c2) break;
        char c3 = msg[i+3]; if (!c3) break;
        // ERROR / Error / error
        if ((c0|0x20) == 'e' && (c1|0x20) == 'r' && (c2|0x20) == 'r' && (c3|0x20) == 'o') {
            return HV_DBGEVT_SEV_ERROR;
        }
        // FAIL / Fail / failed
        if ((c0|0x20) == 'f' && (c1|0x20) == 'a' && (c2|0x20) == 'i' && (c3|0x20) == 'l') {
            return HV_DBGEVT_SEV_ERROR;
        }
        // WARN / Warn / WARNING
        if ((c0|0x20) == 'w' && (c1|0x20) == 'a' && (c2|0x20) == 'r' && (c3|0x20) == 'n') {
            return HV_DBGEVT_SEV_WARN;
        }
    }
    return HV_DBGEVT_SEV_INFO;
}

// Re-entrancy guard — 防止 HvDbgEvtPost 内部 (或 spinlock 持有期间) 再次走到
// 重定义后的 DbgPrint → HvTracePrint → HvDbgEvtPost 二次抢锁 deadlock.
// per-CPU TLS 太重, 用一个简单的 thread-local 模拟: 取当前 KTHREAD 地址低 6 位
// 作 64-slot 表索引 (近似), 进入时原子置位, 重入直接路 1 only (跳过 ring).
extern volatile LONG g_HvTraceReentryGuard[64];

__forceinline ULONG HvTracePrint(_In_ ULONG cat, _In_z_ _Printf_format_string_ PCSTR fmt, ...)
{
    va_list ap;

    // === 路 1: vDbgPrintExWithPrefix → WinDbg (老行为, 永远跑) ===
    va_start(ap, fmt);
    vDbgPrintExWithPrefix("", 0, 3, fmt, ap);
    va_end(ap);

    // === re-entrancy 检查: 进入 HvDbgEvtPost 期间不再 post ===
    // 用 KeGetCurrentProcessorNumber 作 slot. IPI/DPC 内不会切核, 安全.
    ULONG cpu = KeGetCurrentProcessorNumberEx(NULL);
    if (cpu >= 64) cpu = 0;
    if (InterlockedCompareExchange(&g_HvTraceReentryGuard[cpu], 1, 0) != 0) {
        return 0;   // 重入 — 已在 ring path, 跳过避免 deadlock
    }

    // === 路 2: RtlStringCbVPrintfA + 写 ring ===
    char buf[HV_DBGEVT_DETAIL_MAX];
    va_start(ap, fmt);
    NTSTATUS prSt = RtlStringCbVPrintfA(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (!NT_SUCCESS(prSt) && prSt != STATUS_BUFFER_OVERFLOW) {
        InterlockedExchange(&g_HvTraceReentryGuard[cpu], 0);
        return 0;
    }
    // RtlStringCbVPrintfA 截断成功时返 STATUS_BUFFER_OVERFLOW + NUL-terminated.
    // 算长度
    int n = 0;
    while (n < (int)sizeof(buf) - 1 && buf[n]) n++;
    while (n > 0 && (buf[n-1] == '\n' || buf[n-1] == '\r')) {
        buf[--n] = '\0';
    }
    if (n > 0) {
        ULONG sev = HvTracepSeverityFromMsg(buf);
        HvDbgEvtPost(sev, cat, 0, 0, 0, 0, 0, buf);
    }

    InterlockedExchange(&g_HvTraceReentryGuard[cpu], 0);
    return 0;
}

// Redefine DbgPrint. 因为 ntddk.h 把 DbgPrint 声明成函数原型, 我们这里 #define
// 覆盖宏, 编译器后续看到 DbgPrint(...) 全部按宏展开成 HvTracePrint(...).
//
// 注意: 必须在 *所有* ntddk 头 include 之后做, 不然原型解析会冲突.
//        本头 include "HvHook.h" 时 ntddk 已被拉进.
#undef DbgPrint
#define DbgPrint(...)  HvTracePrint(HV_TRACE_THIS_CAT, __VA_ARGS__)

#endif  // !HV_TRACE_DISABLE

#endif  // _HV_TRACE_H_
