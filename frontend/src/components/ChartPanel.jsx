import React from "react";

export default function ChartPanel({ title, children }) {
  return (
    <div className="bg-white rounded shadow p-4">
      <div className="text-lg font-semibold mb-2">{title}</div>
      <div className="overflow-auto">{children}</div>
    </div>
  );
}
