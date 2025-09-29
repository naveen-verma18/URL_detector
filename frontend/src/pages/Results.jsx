import React, { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import api from "../api";
import UrlTable from "../components/UrlTable.jsx";

export default function Results() {
  const { uploadId } = useParams();
  const [summary, setSummary] = useState(null);
  const [results, setResults] = useState([]);
  const [filterMalicious, setFilterMalicious] = useState(false);
  const [filterType, setFilterType] = useState("");

  const load = async () => {
    const res = await api.get(`/results/${uploadId}`);
    setSummary(res.data.summary);
    setResults(res.data.results);
  };

  useEffect(() => {
    load().catch(() => {});
  }, [uploadId]);

  const filtered = results.filter((r) => {
    if (filterMalicious && !r.is_malicious) return false;
    if (filterType && r.attack_type !== filterType) return false;
    return true;
  });

  const download = async (fmt) => {
    const url = api.defaults.baseURL + `/download/${uploadId}/${fmt}`;
    window.open(url, "_blank");
  };

  const types = Array.from(new Set(results.map((r) => r.attack_type))).filter(Boolean);

  return (
    <div className="space-y-4">
      <div className="bg-white rounded shadow p-4">
        <div className="text-lg font-semibold">Summary</div>
        {summary ? (
          <div className="text-sm text-gray-700 mt-2">
            <div>Total URLs: {summary.total_urls}</div>
            <div>Malicious: {summary.malicious_count}</div>
            <div>Time Range: {summary.time_range?.[0]} → {summary.time_range?.[1]}</div>
          </div>
        ) : (
          <div className="text-sm text-gray-500">Loading...</div>
        )}
      </div>

      <div className="bg-white rounded shadow p-4">
        <div className="flex items-center justify-between mb-3">
          <div className="text-lg font-semibold">Results</div>
          <div className="space-x-2">
            <button className="px-3 py-1 bg-gray-200 rounded" onClick={() => download("csv")}>Export CSV</button>
            <button className="px-3 py-1 bg-gray-200 rounded" onClick={() => download("json")}>Export JSON</button>
          </div>
        </div>

        <div className="flex items-center space-x-4 mb-3">
          <label className="flex items-center space-x-2">
            <input type="checkbox" checked={filterMalicious} onChange={(e) => setFilterMalicious(e.target.checked)} />
            <span>Malicious only</span>
          </label>
          <label className="flex items-center space-x-2">
            <span>Attack Type</span>
            <select value={filterType} onChange={(e) => setFilterType(e.target.value)} className="border rounded px-2 py-1">
              <option value="">All</option>
              {types.map((t) => <option key={t} value={t}>{t}</option>)}
            </select>
          </label>
        </div>

        <UrlTable rows={filtered} />
      </div>
    </div>
  );
}
