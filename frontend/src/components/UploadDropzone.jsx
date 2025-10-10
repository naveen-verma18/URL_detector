import React, { useRef, useState } from "react";

export default function UploadDropzone({ onFileSelected }) {
  const ref = useRef(null);
  const [dragOver, setDragOver] = useState(false);

  const onDrop = (e) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files?.[0];
    if (file) onFileSelected(file);
  };

  return (
    <div
      className={`border-2 border-dashed rounded-lg p-8 text-center bg-white ${dragOver ? "border-blue-500" : "border-gray-300"}`}
      onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
      onDragLeave={() => setDragOver(false)}
      onDrop={onDrop}
      onClick={() => ref.current?.click()}
    >
      <div className="text-lg font-semibold">Drop PCAP file here or click to select</div>
      <div className="text-sm text-gray-500 mt-2">Allowed: .pcap, .pcapng (max 100MB)</div>
      <input
        ref={ref}
        type="file"
        accept=".pcap,.pcapng"
        className="hidden"
        onChange={(e) => {
          const file = e.target.files?.[0];
          if (file) onFileSelected(file);
        }}
      />
    </div>
  );
}
