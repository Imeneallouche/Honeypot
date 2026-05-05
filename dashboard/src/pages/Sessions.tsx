import { useQuery } from "@tanstack/react-query";

import { apiClient } from "../api/client";

type SessionRow = {
  id: number;
  honeypot_type: string;
  src_ip: string;
  country?: string | null;
  started_at: string;
  threat_score: number;
};

export default function Sessions() {
  const { data, isPending } = useQuery({
    queryKey: ["sessions"],
    queryFn: async () => {
      const { data } = await apiClient.get<{ items: SessionRow[] }>("/sessions?page=1&page_size=20");
      return data;
    },
  });

  return (
    <div className="space-y-4">
      <h2 className="text-xl font-semibold">Sessions</h2>
      {isPending ? (
        <p className="text-slate-400">Loading…</p>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-slate-800">
          <table className="min-w-full text-sm">
            <thead className="bg-slate-900 text-left text-slate-400">
              <tr>
                <th className="px-3 py-2">ID</th>
                <th className="px-3 py-2">Type</th>
                <th className="px-3 py-2">IP</th>
                <th className="px-3 py-2">Country</th>
                <th className="px-3 py-2">Threat</th>
              </tr>
            </thead>
            <tbody>
              {data?.items.map((row) => (
                <tr key={row.id} className="border-t border-slate-800 hover:bg-slate-900">
                  <td className="px-3 py-2">{row.id}</td>
                  <td className="px-3 py-2">{row.honeypot_type}</td>
                  <td className="px-3 py-2">{row.src_ip}</td>
                  <td className="px-3 py-2">{row.country ?? "—"}</td>
                  <td className="px-3 py-2">{row.threat_score}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
