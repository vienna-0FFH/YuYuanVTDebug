/*
 * HvRegistryHook.h
 *
 * 注册表枚举隐藏 — 阶段 8.2
 *
 * 功能:
 *   - Hook NtEnumerateKey 在父键枚举子键时过滤指定名字
 *   - 不拦截直接路径打开 (NtOpenKey)，使 GUI 可经已知路径访问驱动私有 reg 区
 *   - 设计目标: regedit / sc query / 服务管理器 等枚举工具看不到 "Netr"
 */

#ifndef _HV_REGISTRY_HOOK_H_
#define _HV_REGISTRY_HOOK_H_

#pragma once

#include <ntddk.h>

#define HV_REG_HIDE_TAG     'gRvH'
#define HV_REG_MAX_HIDDEN   16
#define HV_REG_NAME_MAX     64

NTSTATUS HvRegHookInitialize(VOID);
NTSTATUS HvRegHookCleanup(VOID);

NTSTATUS HvRegHookInstall(VOID);
NTSTATUS HvRegHookInstallAtAddress(_In_ PVOID NtEnumerateKeyAddress);
NTSTATUS HvRegHookUninstall(VOID);
BOOLEAN  HvRegHookIsInstalled(VOID);

NTSTATUS HvRegHookAddHiddenKeyName(_In_ PCWSTR KeyName);
NTSTATUS HvRegHookRemoveHiddenKeyName(_In_ PCWSTR KeyName);
BOOLEAN  HvRegHookIsHidden(_In_ PCWSTR Name, _In_ ULONG NameLengthBytes);

#endif
