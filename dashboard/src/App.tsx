import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { Toaster } from "react-hot-toast";

import Layout from "./components/Layout";
import { useAuthStore } from "./store/authStore";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import Sessions from "./pages/Sessions";
import Attackers from "./pages/Attackers";
import Payloads from "./pages/Payloads";
import Alerts from "./pages/Alerts";
import Reports from "./pages/Reports";

const qc = new QueryClient();

function Protected({ children }: { children: JSX.Element }) {
  const token = useAuthStore((s) => s.accessToken);
  if (!token) return <Navigate to="/login" replace />;
  return children;
}

export default function App() {
  return (
    <QueryClientProvider client={qc}>
      <BrowserRouter>
        <Toaster position="top-right" toastOptions={{ className: "text-sm" }} />
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route
            path="/"
            element={
              <Protected>
                <Layout />
              </Protected>
            }
          >
            <Route index element={<Dashboard />} />
            <Route path="sessions" element={<Sessions />} />
            <Route path="attackers" element={<Attackers />} />
            <Route path="payloads" element={<Payloads />} />
            <Route path="alerts" element={<Alerts />} />
            <Route path="reports" element={<Reports />} />
          </Route>
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  );
}
