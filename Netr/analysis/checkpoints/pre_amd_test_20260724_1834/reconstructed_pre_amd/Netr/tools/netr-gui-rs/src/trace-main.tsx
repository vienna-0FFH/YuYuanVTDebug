import React from "react";
import ReactDOM from "react-dom/client";
import { Toaster } from "sonner";
import { ThemeProvider } from "@/components/ThemeProvider";
import { TraceConsoleApp } from "@/trace/TraceConsoleApp";
import "./index.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ThemeProvider>
      <TraceConsoleApp />
      <Toaster richColors closeButton position="bottom-right" />
    </ThemeProvider>
  </React.StrictMode>
);
