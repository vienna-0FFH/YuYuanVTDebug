/*
 * SimpleHypervisor.h - Hypervisor 统一头文件
 * 
 * 这是主要的头文件，包含了所有模块的声明。
 * 项目已拆分为以下模块：
 * 
 * - HvTypes.h   : 类型定义、常量、宏
 * - HvUtils.h/c : 工具函数
 * - HvEpt.h/c   : EPT 操作
 * - HvVmcs.h/c  : VMCS 配置和 VMX 操作
 * - HvVmExit.h/c: VM Exit 处理
 * - HvCore.h/c  : 初始化和核心逻辑
 * - Driver.c    : 驱动入口
 */

#ifndef _SIMPLE_HYPERVISOR_H_
#define _SIMPLE_HYPERVISOR_H_

// 包含所有模块头文件
#include "HvTypes.h"
#include "HvUtils.h"
#include "HvEpt.h"
#include "HvNpt.h"
#include "HvVmcs.h"
#include "HvVmExit.h"
#include "HvCore.h"
#include "EptHook.h"
#include "NptHook.h"

#endif // _SIMPLE_HYPERVISOR_H_
