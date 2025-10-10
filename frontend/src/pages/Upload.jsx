import React, { useState, useEffect } from "react";
import UploadDropzone from "../components/UploadDropzone.jsx";
import api from "../api";
import { useNavigate } from "react-router-dom";

export default function Upload() {
  const [uploadId, setUploadId] = useState(null);
  const [status, setStatus] = useState(null);
  const [filename, setFilename] = useState("");
  const [error, setError] = useState("");
  const navigate = useNavigate();

  const pollStatus = async (id) => {
    try {
      const res = await api.get(`/upload-status/${id}`);
      const s = res.data.status || "";
      setStatus(s);
      setFilename(res.data.filename || "");
      if (s.startsWith("completed")) {
        setTimeout(() => navigate(`/results/${id}`), 500);
      }
      if (s.startsWith("failed")) {
        setError(s);
      }
    } catch (e) {
      setError(String(e));
    }
  };

  useEffect(() => {
    let t;
    if (uploadId) {
      t = setInterval(() => pollStatus(uploadId), 1500);
    }
    return () => clearInterval(t);
  }, [uploadId]);

  const onFileSelected = async (file) => {
    setError("");
    try {
      const form = new FormData();
      form.append("file", file);
      const res = await api.post("/upload-pcap", form, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      setUploadId(res.data.upload_id);
      setStatus(res.data.status);
    } catch (e) {
      setError(String(e?.response?.data?.error || e.message));
    }
  };

  const Step = ({ label, active }) => (
    <div className="flex items-center space-x-2">
      <div className={`w-3 h-3 rounded-full ${active ? "bg-green-500" : "bg-gray-300"}`} />
      <div className={`text-sm ${active ? "text-green-700" : "text-gray-500"}`}>{label}</div>
    </div>
  );

  return (
    <div className="space-y-6">
      <UploadDropzone onFileSelected={onFileSelected} />
      {uploadId && (
        <div className="bg-white rounded-lg shadow p-4">
          <div className="text-sm text-gray-500">Upload ID: {uploadId}</div>
          <div className="text-sm text-gray-500">File: {filename}</div>
          <div className="mt-4 grid grid-cols-1 md:grid-cols-4 gap-3">
            <Step label="Uploaded" active={!!uploadId} />
            <Step label="Parsing" active={status && (status.includes("parsing") || status.includes("predicting") || status.includes("completed"))} />
            <Step label="Predicting" active={status && (status.includes("predicting") || status.includes("completed"))} />
            <Step label="Completed" active={status && status.includes("completed")} />
          </div>
          <div className="mt-2 text-sm">Status: {status}</div>
          {error && <div className="mt-2 text-sm text-red-600">Error: {error}</div>}
        </div>
      )}
    </div>
  );
}
