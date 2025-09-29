import React, { useState } from "react";

function Modal({ open, onClose, record }) {
  if (!open) return null;
  return (
    <div className="fixed inset-0 bg-black/30 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg shadow-lg w-full max-w-2xl p-6">
        <div className="flex justify-between items-center mb-4">
          <div className="text-lg font-semibold">Details</div>
          <button onClick={onClose} className="px-3 py-1 bg-gray-100 rounded">Close</button>
        </div>
        <pre className="text-sm overflow-auto max-h-96">{JSON.stringify(record, null, 2)}</pre>
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
                className={`border-t cursor-pointer ${r.is_malicious ? "bg-red-50" : "bg-green-50"}`}
                onClick={() => onRowClick(r)}
              >
                <td className="p-2">{r.timestamp}</td>
                <td className="p-2">{r.src_ip}</td>
                <td className="p-2">{r.dst_ip}</td>
                <td className="p-2">{r.domain}</td>
                <td className="p-2 max-w-xs truncate">{r.url}</td>
                <td className="p-2">{String(r.is_malicious)}</td>
                <td className="p-2">{r.attack_type}</td>
                <td className="p-2">{String(r.attack_success)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <Modal open={open} onClose={() => setOpen(false)} record={current} />
    </>
  );
}
