import { useQuery } from "@tanstack/react-query";

import { apiClient } from "../api/client";

type TopIp = { ip: string; count: number; country?: string | null };

export default function Attackers() {
  const { data, isPending } = useQuery({
    queryKey: ["attackers-top"],
    queryFn: async () => {
      const { data } = await apiClient.get<TopIp[]>("/attackers/top-ips");
      return data;
    },
  });

  return (
    <div className="space-y-4">
      <h2 className="text-xl font-semibold">Top attacker IPs</h2>
      {isPending ? (
        <p className="text-slate-400">Loading…</p>
      ) : (
        <ul className="space-y-2">
          {(data ?? []).map((row) => (
            <li
              key={row.ip}
              className="flex justify-between rounded border border-slate-800 bg-slate-900 px-4 py-3"
            >
              <span className="font-mono">{row.ip}</span>
              <span className="text-slate-400">{row.count} hits</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
