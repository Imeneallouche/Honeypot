import { useQuery } from "@tanstack/react-query";
import toast from "react-hot-toast";

import { apiClient } from "../api/client";

type ReportRow = {
  id: number;
  generated_at: string;
  period_start: string;
  period_end: string;
  report_type: string;
};

export default function Reports() {
  const { data, refetch, isFetching } = useQuery({
    queryKey: ["reports"],
    queryFn: async () => {
      const { data } = await apiClient.get<{ items: ReportRow[] }>("/reports");
      return data;
    },
  });

  async function generate() {
    await apiClient.post("/reports/generate", { period_days: 7 });
    toast.success("Report queued");
    await refetch();
  }

  async function download(id: number) {
    try {
      const res = await apiClient.get(`/reports/${id}/download`, { responseType: "blob" });
      const url = window.URL.createObjectURL(res.data);
      const a = document.createElement("a");
      a.href = url;
      a.download = `report-${id}.pdf`;
      a.click();
      window.URL.revokeObjectURL(url);
    } catch {
      toast.error("Download failed");
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-semibold">Reports</h2>
        <button
          type="button"
          disabled={isFetching}
          onClick={() => generate().catch(() => toast.error("Failed"))}
          className="rounded bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-500 disabled:opacity-50"
        >
          Generate PDF
        </button>
      </div>
      <ul className="space-y-2">
        {(data?.items ?? []).map((r) => (
          <li key={r.id} className="flex justify-between rounded border border-slate-800 bg-slate-900 px-4 py-3">
            <div>
              <p className="font-medium">Report #{r.id}</p>
              <p className="text-xs text-slate-500">
                {r.period_start.slice(0, 10)} → {r.period_end.slice(0, 10)}
              </p>
            </div>
            <button
              type="button"
              onClick={() => download(r.id)}
              className="text-sm text-emerald-400 hover:underline"
            >
              Download
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}
