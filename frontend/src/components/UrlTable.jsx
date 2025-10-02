import React, { useState } from "react";

// Attack type mapping for user-friendly display
const ATTACK_TYPE_DISPLAY = {
  'benign': { name: 'Benign', color: 'bg-green-100 text-green-800', icon: '✓' },
  'sql_injection': { name: 'SQL Injection', color: 'bg-red-100 text-red-800', icon: '💉' },
  'xss': { name: 'Cross-Site Scripting', color: 'bg-orange-100 text-orange-800', icon: '🔗' },
  'directory_traversal': { name: 'Directory Traversal', color: 'bg-purple-100 text-purple-800', icon: '📁' },
  'command_injection': { name: 'Command Injection', color: 'bg-red-100 text-red-800', icon: '⚡' },
  'ssrf': { name: 'Server-Side Request Forgery', color: 'bg-yellow-100 text-yellow-800', icon: '🌐' },
  'lfi_rfi': { name: 'File Inclusion', color: 'bg-indigo-100 text-indigo-800', icon: '📄' },
  'brute_force': { name: 'Brute Force', color: 'bg-red-100 text-red-800', icon: '🔨' },
  'http_parameter_pollution': { name: 'Parameter Pollution', color: 'bg-pink-100 text-pink-800', icon: '🔀' },
  'xxe': { name: 'XML External Entity', color: 'bg-gray-100 text-gray-800', icon: '📋' },
  'web_shell_upload': { name: 'Web Shell Upload', color: 'bg-red-100 text-red-800', icon: '🐚' },
  'typosquatting': { name: 'Typosquatting', color: 'bg-blue-100 text-blue-800', icon: '🎭' },
  'malicious': { name: 'Malicious', color: 'bg-red-100 text-red-800', icon: '⚠️' },
  'unknown': { name: 'Unknown', color: 'bg-gray-100 text-gray-800', icon: '❓' }
};

function AttackTypeBadge({ attackType }) {
  const display = ATTACK_TYPE_DISPLAY[attackType] || ATTACK_TYPE_DISPLAY['unknown'];
  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${display.color}`}>
      <span className="mr-1">{display.icon}</span>
      {display.name}
    </span>
  );
}

function Modal({ open, onClose, record }) {
  if (!open) return null;
  return (
    <div className="fixed inset-0 bg-black/30 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg shadow-lg w-full max-w-4xl p-6 max-h-[90vh] overflow-y-auto">
        <div className="flex justify-between items-center mb-4">
          <div className="text-lg font-semibold">URL Analysis Details</div>
          <button onClick={onClose} className="px-3 py-1 bg-gray-100 rounded hover:bg-gray-200">Close</button>
        </div>
        
        {/* Key Information */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
          <div className="space-y-2">
            <div><strong>URL:</strong> <span className="break-all">{record?.url}</span></div>
            <div><strong>Domain:</strong> {record?.domain}</div>
            <div><strong>Attack Type:</strong> <AttackTypeBadge attackType={record?.attack_type} /></div>
            <div><strong>ML Prediction:</strong> <AttackTypeBadge attackType={record?.ml_attack_type} /></div>
            <div><strong>Heuristic Type:</strong> <AttackTypeBadge attackType={record?.heuristic_attack_type} /></div>
          </div>
          <div className="space-y-2">
            <div><strong>Source IP:</strong> {record?.src_ip}</div>
            <div><strong>Destination IP:</strong> {record?.dst_ip}</div>
            <div><strong>Timestamp:</strong> {record?.timestamp}</div>
            <div><strong>Status Code:</strong> {record?.status_code || 'N/A'}</div>
            <div><strong>User Agent:</strong> <span className="text-sm break-all">{record?.user_agent || 'N/A'}</span></div>
          </div>
        </div>
        
        {/* Raw JSON */}
        <details className="mt-4">
          <summary className="cursor-pointer font-medium mb-2">Raw Data (JSON)</summary>
          <pre className="text-sm overflow-auto max-h-64 bg-gray-50 p-3 rounded border">{JSON.stringify(record, null, 2)}</pre>
        </details>
      </div>
    </div>
  );
}

export default function UrlTable({ rows }) {
  const [open, setOpen] = useState(false);
  const [current, setCurrent] = useState(null);

  const onRowClick = (r) => {
    setCurrent(r);
    setOpen(true);
  };

  return (
    <>
      <div className="overflow-auto rounded border">
        <table className="min-w-full text-sm">
          <thead className="bg-gray-100 text-left">
            <tr>
              <th className="p-2">Time</th>
              <th className="p-2">Src IP</th>
              <th className="p-2">Dst IP</th>
              <th className="p-2">Domain</th>
              <th className="p-2">URL</th>
              <th className="p-2">Malicious</th>
              <th className="p-2">Attack Type</th>
              <th className="p-2">Attack Success</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r, i) => (
              <tr key={i}
                className={`border-t cursor-pointer hover:bg-gray-50 ${r.is_malicious ? "bg-red-25" : "bg-green-25"}`}
                onClick={() => onRowClick(r)}
              >
                <td className="p-2 text-xs">{r.timestamp?.substring(0, 19) || 'N/A'}</td>
                <td className="p-2 text-sm font-mono">{r.src_ip}</td>
                <td className="p-2 text-sm font-mono">{r.dst_ip}</td>
                <td className="p-2 text-sm">{r.domain}</td>
                <td className="p-2 max-w-xs truncate text-sm" title={r.url}>{r.url}</td>
                <td className="p-2">
                  <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${
                    r.is_malicious ? 'bg-red-100 text-red-800' : 'bg-green-100 text-green-800'
                  }`}>
                    {r.is_malicious ? '⚠️ Yes' : '✓ No'}
                  </span>
                </td>
                <td className="p-2">
                  <AttackTypeBadge attackType={r.attack_type} />
                </td>
                <td className="p-2">
                  <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${
                    r.attack_success ? 'bg-red-100 text-red-800' : 'bg-gray-100 text-gray-800'
                  }`}>
                    {r.attack_success ? '🎯 Success' : '🛡️ Blocked'}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <Modal open={open} onClose={() => setOpen(false)} record={current} />
    </>
  );
}
