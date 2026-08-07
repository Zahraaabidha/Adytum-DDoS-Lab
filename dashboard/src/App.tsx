import { BrowserRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { AppShell } from "./layout/AppShell";
import { AppRoutes } from "./routes";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      retry: 1,
    },
  },
});

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <AppShell>
          <AppRoutes />
        </AppShell>
      </BrowserRouter>
    </QueryClientProvider>
  );
}

export default App
