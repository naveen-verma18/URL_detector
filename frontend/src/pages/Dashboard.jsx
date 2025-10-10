import React, { useEffect, useState } from "react";
import api from "../api";
import { LineChart, Line, XAxis, YAxis, Tooltip, CartesianGrid, BarChart, Bar, PieChart, Pie, Legend, Cell } from "recharts";
import ChartPanel from "../components/ChartPanel.jsx";

const COLORS = ["#ef4444", "#f59e0b", "#10b981", "#3b82f6", "#8b5cf6", "#ec4899"];

export default function Dashboard() {
  const [items, setItems] = useState([]);

  useEffect(() => {
    (async () => {
      const res = await api.get("/history?page=1&page_size=100");
      setItems(res.data.items || []);
    })();
  }, []);

  // Fake timeseries: treat uploaded_at as x
  const series = items.map((it) => ({
    time: it.uploaded_at,
    malicious: it.malicious_count || 0,
  }));

  // Placeholder top domains; a richer aggregate would compute across results
  const topDomains = items
    .map((it) => ({ domain: it.filename, count: it.malicious_count || 0 }))
    .slice(0, 10);

  const typeBreakdown = [
    // Placeholder data; add a /dashboard endpoint to compute real aggregates
    { name: "phishing", value: 4 },
    { name: "malware-download", value: 2 },
    { name: "suspicious-redirect", value: 3 },
    { name: "unknown", value: 5 }
  ];

  return (
    <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
      <ChartPanel title="Malicious URLs Over Time">
        <LineChart width={520} height={280} data={series}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="time" hide />
          <YAxis />
          <Tooltip />
          <Legend />
          <Line type="monotone" dataKey="malicious" stroke="#ef4444" />
        </LineChart>
      </ChartPanel>

      <ChartPanel title="Top Malicious Domains (by upload)">
        <BarChart width={520} height={280} data={topDomains}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="domain" hide />
          <YAxis />
          <Tooltip />
          <Bar dataKey="count" fill="#3b82f6" />
        </BarChart>
      </ChartPanel>

      <ChartPanel title="Attack Types Distribution">
        <PieChart width={520} height={280}>
          <Pie dataKey="value" data={typeBreakdown} cx="50%" cy="50%" outerRadius={100} label>
            {typeBreakdown.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
            ))}
          </Pie>
          <Tooltip />
          <Legend />
        </PieChart>
      </ChartPanel>
    </div>
  );
}
