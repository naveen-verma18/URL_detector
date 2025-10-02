import React, { useEffect, useState } from "react";
import api from "../api";
import { LineChart, Line, XAxis, YAxis, Tooltip, CartesianGrid, BarChart, Bar, PieChart, Pie, Legend, Cell } from "recharts";
import ChartPanel from "../components/ChartPanel.jsx";

const COLORS = ["#10b981", "#ef4444", "#f59e0b", "#3b82f6", "#8b5cf6", "#ec4899", "#6b7280", "#f97316", "#06b6d4", "#84cc16", "#a855f7", "#e11d48"];

// Attack type display mapping
const ATTACK_TYPE_DISPLAY = {
  'benign': { name: 'Benign', color: '#10b981', icon: '✓' },
  'sql_injection': { name: 'SQL Injection', color: '#ef4444', icon: '💉' },
  'xss': { name: 'Cross-Site Scripting', color: '#f59e0b', icon: '🔗' },
  'directory_traversal': { name: 'Directory Traversal', color: '#8b5cf6', icon: '📁' },
  'command_injection': { name: 'Command Injection', color: '#ef4444', icon: '⚡' },
  'ssrf': { name: 'Server-Side Request Forgery', color: '#f59e0b', icon: '🌐' },
  'lfi_rfi': { name: 'File Inclusion', color: '#3b82f6', icon: '📄' },
  'brute_force': { name: 'Brute Force', color: '#ef4444', icon: '🔨' },
  'http_parameter_pollution': { name: 'Parameter Pollution', color: '#ec4899', icon: '🔀' },
  'xxe': { name: 'XML External Entity', color: '#6b7280', icon: '📋' },
  'web_shell_upload': { name: 'Web Shell Upload', color: '#ef4444', icon: '🐚' },
  'typosquatting': { name: 'Typosquatting', color: '#3b82f6', icon: '🎭' },
  'malicious': { name: 'Malicious', color: '#ef4444', icon: '⚠️' },
  'unknown': { name: 'Unknown', color: '#6b7280', icon: '❓' }
};

export default function Dashboard() {
  const [items, setItems] = useState([]);
  const [attackStats, setAttackStats] = useState({});

  useEffect(() => {
    (async () => {
      const res = await api.get("/history?page=1&page_size=100");
      setItems(res.data.items || []);
      
      // Aggregate attack type statistics from all uploads
      const stats = {};
      let totalAttacks = 0;
      
      for (const item of res.data.items || []) {
        try {
          // Try to fetch results for each upload to get attack type breakdown
          const resultRes = await api.get(`/results/${item.upload_id}`);
          const results = resultRes.data.results || [];
          
          for (const result of results) {
            if (result.is_malicious) {
              const attackType = result.attack_type || result.ml_attack_type || 'unknown';
              stats[attackType] = (stats[attackType] || 0) + 1;
              totalAttacks++;
            }
          }
        } catch (e) {
          // Skip if can't fetch results
        }
      }
      
      setAttackStats({ ...stats, totalAttacks });
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

  // Convert attack stats to chart data
  const typeBreakdown = Object.entries(attackStats)
    .filter(([key]) => key !== 'totalAttacks')
    .map(([type, count]) => ({
      name: ATTACK_TYPE_DISPLAY[type]?.name || type,
      value: count,
      type: type,
      color: ATTACK_TYPE_DISPLAY[type]?.color || '#6b7280'
    }))
    .sort((a, b) => b.value - a.value);

  return (
    <div className="space-y-6">
      {/* Attack Type Statistics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-white rounded-lg shadow p-6 text-center">
          <div className="text-sm text-gray-500">Total Uploads</div>
          <div className="text-3xl font-bold mt-2">{items.length}</div>
        </div>
        <div className="bg-white rounded-lg shadow p-6 text-center">
          <div className="text-sm text-gray-500">Total URLs</div>
          <div className="text-3xl font-bold mt-2">{items.reduce((sum, item) => sum + (item.total_urls || 0), 0)}</div>
        </div>
        <div className="bg-white rounded-lg shadow p-6 text-center">
          <div className="text-sm text-gray-500">Malicious URLs</div>
          <div className="text-3xl font-bold mt-2 text-red-600">{items.reduce((sum, item) => sum + (item.malicious_count || 0), 0)}</div>
        </div>
        <div className="bg-white rounded-lg shadow p-6 text-center">
          <div className="text-sm text-gray-500">Attack Types</div>
          <div className="text-3xl font-bold mt-2 text-blue-600">{typeBreakdown.length}</div>
        </div>
      </div>

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

        <ChartPanel title="Attack Types Distribution">
          {typeBreakdown.length > 0 ? (
            <PieChart width={520} height={280}>
              <Pie 
                dataKey="value" 
                data={typeBreakdown} 
                cx="50%" 
                cy="50%" 
                outerRadius={100} 
                label={({ name, value }) => `${name}: ${value}`}
              >
                {typeBreakdown.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip formatter={(value, name) => [value, name]} />
              <Legend />
            </PieChart>
          ) : (
            <div className="flex items-center justify-center h-64 text-gray-500">
              No attack data available. Upload some PCAP files to see statistics.
            </div>
          )}
        </ChartPanel>

        <ChartPanel title="Attack Types Breakdown">
          {typeBreakdown.length > 0 ? (
            <div className="space-y-3">
              {typeBreakdown.map((item, index) => (
                <div key={index} className="flex items-center justify-between p-3 bg-gray-50 rounded">
                  <div className="flex items-center space-x-3">
                    <div 
                      className="w-4 h-4 rounded-full" 
                      style={{ backgroundColor: item.color }}
                    ></div>
                    <span className="font-medium">{ATTACK_TYPE_DISPLAY[item.type]?.icon} {item.name}</span>
                  </div>
                  <span className="font-bold text-lg">{item.value}</span>
                </div>
              ))}
            </div>
          ) : (
            <div className="flex items-center justify-center h-64 text-gray-500">
              No attack data available
            </div>
          )}
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
      </div>
    </div>
  );
}
