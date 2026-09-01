# Netr Control (Tauri + Rust)

Netr Hypervisor 的下一代控制台。替代旧的 Python + Qt 版本。

## 技术栈

- **Tauri 2** — 桌面壳子,Rust 后端 + WebView 前端
- **React 18 + TypeScript + Vite** — 前端
- **Tailwind CSS + shadcn 风格组件** — UI
- **React Router** — 路由
- **Zustand** — 状态管理
- **lucide-react** — 图标
- **sonner** — toast
- **yuyuan-client**(Phase 1+) — 网络验证 SDK

## 开发

```bash
# 一次性安装前端依赖
npm install

# 启动开发模式(自动起前端 dev server + Tauri 窗口)
npm run tauri:dev

# 打包发行版
npm run tauri:build
```

## 目录约定

```
src/                # React 前端
  components/
    layout/         # Shell / TitleBar / Sidebar / Header / StatusBar
    ui/             # shadcn 基础组件
  pages/            # 各业务页面
  store/            # Zustand stores
  lib/              # 工具函数
src-tauri/          # Rust 后端
  src/
    lib.rs          # 入口
    commands/       # Tauri command(Phase 1+)
    ioctl/          # Driver 通信(Phase 3+)
    license/        # 网络验证(Phase 1+)
```

## Phase 路线

- [x] **Phase 0** — 脚手架 + 双主题 + 布局
- [ ] **Phase 1** — 网络验证登录(yuyuan-client)
- [ ] **Phase 2** — Driver SubmitLicense IOCTL + 内核 ed25519 验签
- [ ] **Phase 3** — IOCTL 抽象层(Rust 端)
- [ ] **Phase 4** — ServicePage(SCM 完整)
- [ ] **Phase 5** — Dashboard(指标 + 曲线 + 事件流)
- [ ] **Phase 6** — dbgevt poller
- [ ] **Phase 7** — 剩下 10 个 page
- [ ] **Phase 8** — 打磨(toast / 加载态 / 热键 / 自动更新)
