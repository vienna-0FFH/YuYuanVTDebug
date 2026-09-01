/**
 * 签名预设类型定义 (P99 起改用项目级 sig_store).
 *
 * 不再维护硬编码签名 — 引擎和编译选项一变就失效, 误导大于帮助.
 * 真正用的是后端 SignatureStore: 用户/AI 通过 sig_derive + sig_test 动态发现,
 * sig_save 持久化到 .gmproj. 此文件保留类型给 GlobalsPanel / AobPanel 兼容.
 */

export type SigScope = "main_module" | "all" | "specific_module";

export interface SignaturePreset {
  id: string;
  name: string;
  engine: string[];
  pattern: string;
  follow_rip: boolean;
  scope: string;
  description: string;
}

export const SIGNATURES: SignaturePreset[] = [];

export function signaturesForEngine(_engineKind: string): SignaturePreset[] {
  return SIGNATURES;
}
