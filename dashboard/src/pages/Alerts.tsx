import { useQuery } from "@tanstack/react-query";

import { apiClient } from "../api/client";

type AlertRow = {
  id: number;
  rule_name: string;
  severity: string;
  description: string;
  src_ip: string;
  triggered_at: string;
};

export default function Alerts() {
  const { data, isPending } = useQuery({
    queryKey: ["alerts"],
    queryFn: async () => {
      const { data } = await apiClient.get<{ items: AlertRow[] }>("/alerts?page=1");
      return data;
    },
  });

  return (
    <div className="space-y-4">
      <h2 className="text-xl font-semibold">Alerts</h2>
      {isPending ? (
        <p className="text-slate-400">Loading…</p>
      ) : (
        <ul className="space-y-2">
          {(data?.items ?? []).map((a) => (
            <li key={a.id} className="rounded border border-slate-800 bg-slate-900 p-4">
              <div className="flex justify-between text-sm font-medium">
                <span>{a.rule_name}</span>
                <span className="text-amber-400">{a.severity}</span>
              </div>
              <p className="mt-2 text-xs text-slate-400">{a.description}</p>
              <p className="mt-1 font-mono text-xs text-slate-500">{a.src_ip}</p>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
