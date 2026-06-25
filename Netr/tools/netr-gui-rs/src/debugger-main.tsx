import React from "react";
import ReactDOM from "react-dom/client";
import { Toaster } from "sonner";
import { ThemeProvider } from "@/components/ThemeProvider";
import { DebuggerApp } from "@/debugger/DebuggerApp";
import "./index.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ThemeProvider>
      <DebuggerApp />
      <Toaster richColors closeButton position="bottom-right" />
    </ThemeProvider>
  </React.StrictMode>
);
