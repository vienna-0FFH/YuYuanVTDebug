import { RouterProvider } from "react-router-dom";
import { Toaster } from "sonner";
import { ThemeProvider } from "@/components/ThemeProvider";
import { router } from "@/routes";

export default function App() {
  return (
    <ThemeProvider>
      <RouterProvider router={router} />
      <Toaster richColors closeButton position="bottom-right" />
    </ThemeProvider>
  );
}
