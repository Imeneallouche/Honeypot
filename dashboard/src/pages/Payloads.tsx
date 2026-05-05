import { useQuery } from "@tanstack/react-query";

import { apiClient } from "../api/client";

type Item = {
  id: number;
  src_ip: string;
  payload_type: string;
  severity: string;
  raw_payload: string;
};

export default function Payloads() {
  const { data, isPending } = useQuery({
    queryKey: ["payloads"],
    queryFn: async () => {
      const { data } = await apiClient.get<{ items: Item[] }>("/payloads?page=1&page_size=20");
      return data;
    },
  });

  return (
    <div className="space-y-4">
      <h2 className="text-xl font-semibold">Payloads</h2>
      {isPending ? (
        <p className="text-slate-400">Loading…</p>
      ) : (
        <div className="space-y-3">
          {data?.items.map((p) => (
            <div key={p.id} className="rounded border border-slate-800 bg-slate-900 p-4 text-sm">
              <div className="flex justify-between text-slate-400">
                <span>{p.src_ip}</span>
                <span>
                  {p.payload_type} · {p.severity}
                </span>
              </div>
              <pre className="mt-2 whitespace-pre-wrap break-all text-xs text-emerald-200">{p.raw_payload}</pre>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
