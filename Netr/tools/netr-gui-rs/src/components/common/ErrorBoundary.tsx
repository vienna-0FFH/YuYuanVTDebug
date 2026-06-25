import { Component, type ReactNode, type ErrorInfo } from "react";
import { AlertCircle, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";

interface Props {
  children: ReactNode;
}

interface State {
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    // 仅控制台打印,避免无意外发场景
    console.error("[ErrorBoundary]", error, info.componentStack);
  }

  reset = () => this.setState({ error: null });

  render() {
    if (this.state.error) {
      return (
        <div className="flex h-full min-h-[40vh] flex-col items-center justify-center gap-3 p-8 text-center">
          <AlertCircle className="h-10 w-10 text-destructive" />
          <h2 className="text-lg font-semibold">渲染异常</h2>
          <p className="max-w-lg text-sm text-muted-foreground">
            {this.state.error.message || String(this.state.error)}
          </p>
          <Button variant="outline" onClick={this.reset}>
            <RefreshCw className="h-4 w-4" /> 重试
          </Button>
        </div>
      );
    }
    return this.props.children;
  }
}
