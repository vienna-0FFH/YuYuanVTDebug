import { createBrowserRouter } from "react-router-dom";
import { Shell } from "@/components/layout/Shell";
import { AuthGuard } from "@/components/auth/AuthGuard";
import { RequireDriver } from "@/components/common/RequireDriver";
import Login from "@/pages/Login";
import Register from "@/pages/Register";
import Topup from "@/pages/Topup";
import Account from "@/pages/Account";
import Dashboard from "@/pages/Dashboard";
import Service from "@/pages/Service";
import Status from "@/pages/Status";
import Dse from "@/pages/Dse";
import HideProcess from "@/pages/HideProcess";
import HideDriver from "@/pages/HideDriver";
import Debugger from "@/pages/Debugger";
import LaunchDebugger from "@/pages/LaunchDebugger";
import Memory from "@/pages/Memory";
import Inject from "@/pages/Inject";
import Hwbp from "@/pages/Hwbp";
import InputPage from "@/pages/Input";

/** 包装需要驱动就绪的页面 */
function gated(node: React.ReactNode) {
  return <RequireDriver>{node}</RequireDriver>;
}

export const router = createBrowserRouter([
  { path: "/login", element: <Login /> },
  { path: "/register", element: <Register /> },
  { path: "/topup", element: <Topup /> },
  {
    element: <AuthGuard />,
    children: [
      {
        path: "/",
        element: <Shell />,
        children: [
          // 不受驱动状态约束 — Dashboard / 服务 / 账号
          { index: true, element: <Dashboard /> },
          { path: "service", element: <Service /> },
          { path: "account", element: <Account /> },

          // 以下页面依赖驱动 + 设备 handle
          { path: "status", element: gated(<Status />) },
          { path: "dse", element: gated(<Dse />) },
          { path: "process-hide", element: gated(<HideProcess />) },
          { path: "driver-hide", element: gated(<HideDriver />) },
          { path: "debugger", element: gated(<Debugger />) },
          { path: "launch-debugger", element: gated(<LaunchDebugger />) },
          { path: "memory", element: gated(<Memory />) },
          { path: "inject", element: gated(<Inject />) },
          { path: "hwbp", element: gated(<Hwbp />) },
          { path: "input", element: gated(<InputPage />) },
        ],
      },
    ],
  },
]);
