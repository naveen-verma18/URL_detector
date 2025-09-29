import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import api from "../api";

export default function Home() {
  const [stats, setStats] = useState({ uploads: 0, urls: 0, malicious: 0 });

  useEffect(() => {
    // Aggregate from history
    (async () => {
      try {
        const res = await api.get("/history?page=1&page_size=100");
        const items = res.data.items || [];
        let uploads = items.length;
        let urls = 0;
        let malicious = 0;
        for (const it of items) {
          urls += it.total_urls || 0;
          malicious += it.malicious_count || 0;
        }
        setStats({ uploads, urls, malicious });
      } catch (e) {
        // swallow
      }
    })();
  }, []);

  const Card = ({ title, value }) => (
    <div className="bg-white rounded-lg shadow p-6 text-center">
      <div className="text-sm text-gray-500">{title}</div>
      <div className="text-3xl font-bold mt-2">{value}</div>
    </div>
  );

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card title="Total Uploads" value={stats.uploads} />
        <Card title="Total URLs Parsed" value={stats.urls} />
        <Card title="Total Malicious" value={stats.malicious} />
      </div>

      <div className="flex items-center justify-between">
        <h2 className="text-xl font-semibold">Quick Actions</h2>
        <Link
          to="/upload"
          className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
        >
          Upload PCAP
        </Link>
      </div>
    </div>
  );
}
