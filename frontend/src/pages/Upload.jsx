import React, { useState, useEffect } from "react";
import UploadDropzone from "../components/UploadDropzone.jsx";
import api from "../api";
import { useNavigate } from "react-router-dom";

export default function Upload() {
  const [uploadId, setUploadId] = useState(null);
  const [status, setStatus] = useState(null);
  const [filename, setFilename] = useState("");
  const [error, setError] = useState("");
  const [uploadProgress, setUploadProgress] = useState(0);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadComplete, setUploadComplete] = useState(false);
  const [recentUploads, setRecentUploads] = useState([]);
  const navigate = useNavigate();

  const fetchRecentUploads = async () => {
    try {
      const res = await api.get("/history?page=1&page_size=5");
      setRecentUploads(res.data.items || []);
    } catch (e) {
      console.error("Error fetching recent uploads:", e);
    }
  };

  const pollStatus = async (id) => {
    try {
      const res = await api.get(`/upload-status/${id}`);
      const s = res.data.status || "";
      console.log("Poll status response:", s);
      setStatus(s);
      setFilename(res.data.filename || "");
      if (s.includes("completed") || s.includes("done")) {
        console.log("Upload completed! Redirecting to dashboard...");
        setUploadComplete(true);
        fetchRecentUploads(); // Refresh the list
        setTimeout(() => {
          console.log("Navigating to /dashboard");
          navigate(`/dashboard`);
        }, 2000);
      }
      if (s.includes("failed") || s.includes("error")) {
        setError(s);
        setIsUploading(false);
      }
    } catch (e) {
      console.error("Poll status error:", e);
      setError(String(e));
      setIsUploading(false);
    }
  };

  useEffect(() => {
    fetchRecentUploads(); // Load recent uploads on mount
  }, []);

  useEffect(() => {
    let t;
    if (uploadId) {
      t = setInterval(() => pollStatus(uploadId), 1500);
    }
    return () => clearInterval(t);
  }, [uploadId]);

  const onFileSelected = async (file) => {
    setError("");
    setIsUploading(true);
    setUploadProgress(0);
    setUploadComplete(false);
    setFilename(file.name);
    
    console.log("Uploading file:", file.name, "Size:", file.size);
    
    try {
      const form = new FormData();
      form.append("file", file);
      
      // Simulate upload progress
      const progressInterval = setInterval(() => {
        setUploadProgress(prev => {
          if (prev >= 90) {
            clearInterval(progressInterval);
            return prev;
          }
          return prev + 10;
        });
      }, 200);
      
      console.log("Sending POST request to /upload-pcap");
      const res = await api.post("/upload-pcap", form, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      
      console.log("Upload response:", res.data);
      clearInterval(progressInterval);
      setUploadProgress(100);
      setUploadId(res.data.upload_id);
      setStatus(res.data.status || "Upload complete");
      
      // If no status polling needed, show complete immediately
      if (!res.data.upload_id) {
        setUploadComplete(true);
      }
    } catch (e) {
      console.error("Upload error:", e);
      const errorMsg = e?.response?.data?.error || e?.response?.data?.detail || e.message || "Unknown error occurred";
      setError(errorMsg);
      setIsUploading(false);
      setUploadProgress(0);
    }
  };

  const cancelUpload = () => {
    setIsUploading(false);
    setUploadProgress(0);
    setUploadId(null);
    setFilename("");
    setStatus(null);
    setUploadComplete(false);
  };

  return (
    <div className="space-y-8 max-w-4xl mx-auto">
      {/* Header */}
      <div className="bg-gray-100 rounded-lg p-6 shadow-md">
        <h1 className="text-4xl font-bold text-gray-900 mb-2">Upload New Dataset</h1>
        <p className="text-gray-600">
          Upload PCAP, CSV, or JSON files to train and evaluate your cybersecurity models.
        </p>
      </div>

      {/* Upload Dropzone */}
      <UploadDropzone onFileSelected={onFileSelected} disabled={isUploading} />

      {/* Upload Progress Section */}
      {isUploading && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-xl font-semibold text-gray-900">Uploading File</h2>
            {uploadId && (
              <span className="text-sm text-gray-500">Upload ID: {uploadId}</span>
            )}
          </div>
          
          {/* File Info Card */}
          <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
            <div className="flex items-center gap-3">
              <div className="bg-blue-100 p-3 rounded-lg">
                <svg className="w-6 h-6 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
              </div>
              <div className="flex-1">
                <div className="font-semibold text-gray-900">{filename}</div>
                <div className="text-sm text-gray-600">PCAP File</div>
              </div>
            </div>
          </div>
          
          {/* Progress Bar */}
          <div className="bg-white border border-gray-200 rounded-lg shadow p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-medium text-gray-700">Upload Progress</span>
              <div className="flex items-center gap-4">
                <span className="text-gray-700 text-sm font-medium">{uploadProgress}%</span>
                {!uploadComplete && (
                  <button
                    onClick={cancelUpload}
                    className="text-gray-500 hover:text-gray-700"
                    title="Cancel upload"
                  >
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                    </svg>
                  </button>
                )}
              </div>
            </div>
            
            {/* Progress Bar */}
            <div className="w-full bg-gray-200 rounded-full h-2 overflow-hidden">
              <div
                className="bg-blue-500 h-2 transition-all duration-300 ease-out"
                style={{ width: `${uploadProgress}%` }}
              />
            </div>
            
            {/* Status Text */}
            {status && (
              <div className="mt-2 text-sm text-gray-700 font-medium">
                Status: <span className="text-blue-600">{status}</span>
              </div>
            )}
          </div>

          {/* View Dashboard Button - Show when upload ID exists */}
          {uploadId && uploadProgress === 100 && (
            <div className="bg-white border border-gray-200 rounded-lg shadow p-4">
              <div className="flex items-center justify-between">
                <div>
                  <div className="font-medium text-gray-900">Processing complete!</div>
                  <div className="text-sm text-gray-600">Your file has been analyzed</div>
                </div>
                <button
                  onClick={() => navigate(`/dashboard`)}
                  className="px-6 py-2.5 bg-blue-600 text-white rounded-lg hover:bg-blue-700 font-medium"
                >
                  View Dashboard
                </button>
              </div>
            </div>
          )}

          {/* Success Message */}
          {uploadComplete && (
            <div className="bg-green-50 border border-green-200 rounded-lg p-4">
              <div className="flex items-start gap-3">
                <svg className="w-5 h-5 text-green-600 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <div className="flex-1">
                  <p className="text-green-800 text-sm font-medium mb-2">
                    Upload complete. Dataset '{filename}' successfully ingested.
                  </p>
                  <button
                    onClick={() => navigate(`/dashboard`)}
                    className="px-4 py-2 bg-green-600 text-white rounded hover:bg-green-700 text-sm font-medium"
                  >
                    View Dashboard Now
                  </button>
                  <p className="text-green-700 text-xs mt-2">
                    Redirecting to Dashboard in 2 seconds...
                  </p>
                </div>
              </div>
            </div>
          )}

          {/* Error Message */}
          {error && (
            <div className="bg-red-50 border border-red-200 rounded-lg p-4 flex items-start gap-3">
              <svg className="w-5 h-5 text-red-600 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              <div>
                <p className="text-red-800 text-sm font-medium">Error: {error}</p>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Recent Uploads Section */}
      {recentUploads.length > 0 && (
        <div className="mt-12">
          <h2 className="text-2xl font-bold text-gray-900 mb-4">Recent Uploads</h2>
          <div className="bg-white rounded-lg shadow overflow-hidden">
            <table className="w-full">
              <thead className="bg-gray-50 border-b border-gray-200">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Filename
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Uploaded
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Total URLs
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Malicious
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {recentUploads.map((upload) => (
                  <tr key={upload.id} className="hover:bg-gray-50">
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center">
                        <svg className="w-5 h-5 text-gray-400 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                        </svg>
                        <span className="text-sm font-medium text-gray-900">{upload.filename}</span>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {new Date(upload.uploaded_at).toLocaleString()}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                      {upload.total_urls || 0}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`text-sm font-medium ${
                        upload.malicious_count > 0 ? 'text-red-600' : 'text-green-600'
                      }`}>
                        {upload.malicious_count || 0}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className="px-2 py-1 text-xs rounded bg-green-100 text-green-800">
                        Completed
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm">
                      <button
                        onClick={() => navigate(`/results/${upload.id}`)}
                        className="text-blue-600 hover:text-blue-800 font-medium"
                      >
                        View Results
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
