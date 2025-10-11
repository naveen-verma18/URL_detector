import React, { useRef, useState } from "react";

export default function UploadDropzone({ onFileSelected, disabled }) {
  const ref = useRef(null);
  const [dragOver, setDragOver] = useState(false);

  const onDrop = (e) => {
    e.preventDefault();
    setDragOver(false);
    if (disabled) return;
    const file = e.dataTransfer.files?.[0];
    if (file) onFileSelected(file);
  };

  const handleClick = () => {
    if (!disabled) ref.current?.click();
  };

  return (
    <div
      className={`border-2 border-dashed rounded-lg p-16 text-center transition-all ${
        disabled 
          ? "bg-gray-100 border-gray-300 cursor-not-allowed opacity-50" 
          : dragOver 
            ? "bg-blue-50 border-blue-500 cursor-pointer" 
            : "bg-gray-50 border-gray-400 cursor-pointer hover:border-blue-400 hover:bg-blue-50"
      }`}
      onDragOver={(e) => { 
        e.preventDefault(); 
        if (!disabled) setDragOver(true); 
      }}
      onDragLeave={() => setDragOver(false)}
      onDrop={onDrop}
      onClick={handleClick}
    >
      {/* Upload Icon */}
      <div className="flex justify-center mb-6">
        <svg 
          className="w-16 h-16 text-gray-400" 
          fill="none" 
          stroke="currentColor" 
          viewBox="0 0 24 24"
        >
          <path 
            strokeLinecap="round" 
            strokeLinejoin="round" 
            strokeWidth={1.5} 
            d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" 
          />
        </svg>
      </div>

      {/* Main Text */}
      <div className="text-xl font-semibold text-gray-700 mb-2">
        Drag and drop files here
      </div>

      {/* Subtext */}
      <div className="text-sm text-gray-500 mb-4">
        Or click to browse your files. Supported formats: PCAP, CSV, JSON.
      </div>
      <div className="text-xs text-gray-400">
        Maximum file size: 100MB
      </div>

      {/* Browse Button */}
      <button
        type="button"
        disabled={disabled}
        className="mt-6 px-6 py-2.5 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors inline-flex items-center gap-2"
        onClick={(e) => {
          e.stopPropagation();
          if (!disabled) ref.current?.click();
        }}
      >
        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
        </svg>
        Browse Files
      </button>

      <input
        ref={ref}
        type="file"
        accept=".pcap,.pcapng,.csv,.json"
        className="hidden"
        disabled={disabled}
        onChange={(e) => {
          const file = e.target.files?.[0];
          if (file) onFileSelected(file);
        }}
      />
    </div>
  );
}
