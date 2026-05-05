import { useQuery } from "@tanstack/react-query";
import { Bar, BarChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Activity } from "lucide-react";
import { MapContainer, TileLayer, CircleMarker } from "react-leaflet";
import "leaflet/dist/leaflet.css";

import { apiClient } from "../api/client";
import { useLiveFeed } from "../api/hooks/useLiveFeed";

type Overview = {
  total_sessions_24h: number;
  total_sessions_7d: number;
  unique_ips_24h: number;
  sessions_per_hour_last_24h: { hour: string; count: number }[];
  attack_types_breakdown: Record<string, number>;
};

export default function Dashboard() {
  const { data, isPending } = useQuery({
    queryKey: ["stats-overview"],
    queryFn: async () => {
      const { data } = await apiClient.get<Overview>("/stats/overview");
      return data;
    },
  });

  const { events, isConnected } = useLiveFeed();

  const chartData =
    data?.sessions_per_hour_last_24h?.map((h) => ({
      hour: new Date(h.hour).toLocaleTimeString([], { hour: "2-digit" }),
      count: h.count,
    })) ?? [];

  return (
    <div className="space-y-8">
      <div className="flex items-center gap-3">
        <Activity className="h-8 w-8 text-emerald-400" />
        <div>
          <h2 className="text-2xl font-semibold">Overview</h2>
          <p className="text-sm text-slate-400">
            Live feed: {isConnected ? "connected" : "reconnecting…"}
          </p>
        </div>
      </div>

      {isPending ? (
        <p className="text-slate-400">Loading statistics…</p>
      ) : (
        <>
          <div className="grid gap-4 sm:grid-cols-3">
            <StatCard label="Sessions (24h)" value={data?.total_sessions_24h ?? 0} />
            <StatCard label="Sessions (7d)" value={data?.total_sessions_7d ?? 0} />
            <StatCard label="Unique IPs (24h)" value={data?.unique_ips_24h ?? 0} />
          </div>

          <div className="grid gap-6 lg:grid-cols-2">
            <div className="rounded-xl border border-slate-800 bg-slate-900 p-4">
              <h3 className="mb-4 font-medium">Sessions / hour</h3>
              <div className="h-56">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={chartData}>
                    <XAxis dataKey="hour" stroke="#64748b" fontSize={10} />
                    <YAxis stroke="#64748b" fontSize={10} />
                    <Tooltip />
                    <Bar dataKey="count" fill="#34d399" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>

            <div className="h-72 overflow-hidden rounded-xl border border-slate-800">
              <MapContainer center={[20, 0]} zoom={2} style={{ height: "100%", width: "100%" }}>
                <TileLayer url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png" />
                <CircleMarker center={[52.52, 13.405]} radius={12} pathOptions={{ color: "#34d399" }} />
                <CircleMarker center={[37.7749, -122.4194]} radius={10} pathOptions={{ color: "#38bdf8" }} />
              </MapContainer>
            </div>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900 p-4">
            <h3 className="mb-2 font-medium">Live events</h3>
            <ul className="max-h-48 space-y-1 overflow-y-auto text-xs text-slate-300 font-mono">
              {events.length === 0 && <li className="text-slate-500">Waiting for feed rows…</li>}
              {events.map((evt, idx) => (
                <li key={idx}>{JSON.stringify(evt)}</li>
              ))}
            </ul>
          </div>
        </>
      )}
    </div>
  );
}

function StatCard({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900 px-5 py-4">
      <p className="text-sm text-slate-400">{label}</p>
      <p className="mt-1 text-3xl font-semibold text-white">{value}</p>
    </div>
  );
}
