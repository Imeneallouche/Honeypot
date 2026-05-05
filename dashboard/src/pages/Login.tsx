import { type FormEvent, useState } from "react";
import { useNavigate } from "react-router-dom";
import toast from "react-hot-toast";

import { apiClient } from "../api/client";
import { useAuthStore } from "../store/authStore";

export default function Login() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const setTokens = useAuthStore((s) => s.setTokens);
  const navigate = useNavigate();

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    try {
      const body = new URLSearchParams({ username, password });
      const { data } = await apiClient.post<{
        access_token: string;
        refresh_token: string;
      }>("/auth/login", body, {
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
      });
      setTokens(data.access_token, data.refresh_token);
      toast.success("Signed in");
      navigate("/");
    } catch {
      toast.error("Invalid credentials");
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-950 px-4">
      <form
        onSubmit={onSubmit}
        className="w-full max-w-md space-y-6 rounded-xl border border-slate-800 bg-slate-900 p-8 shadow-xl"
      >
        <div>
          <h1 className="text-2xl font-semibold text-white">Command Center</h1>
          <p className="text-sm text-slate-400">Honeypot intelligence login</p>
        </div>
        <label className="block text-sm font-medium text-slate-300">
          Username
          <input
            className="mt-1 w-full rounded border border-slate-700 bg-slate-950 px-3 py-2 text-white"
            value={username}
            onChange={(ev) => setUsername(ev.target.value)}
          />
        </label>
        <label className="block text-sm font-medium text-slate-300">
          Password
          <input
            type="password"
            className="mt-1 w-full rounded border border-slate-700 bg-slate-950 px-3 py-2 text-white"
            value={password}
            onChange={(ev) => setPassword(ev.target.value)}
          />
        </label>
        <button
          type="submit"
          className="w-full rounded-lg bg-emerald-600 py-2 font-medium text-white hover:bg-emerald-500"
        >
          Sign in
        </button>
      </form>
    </div>
  );
}
