import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import api from "../api";

export default function Home() {
  const [stats, setStats] = useState({ uploads: 0, urls: 0, malicious: 0, attackTypes: 0 });

  useEffect(() => {
    // Aggregate from history
    (async () => {
      try {
        const res = await api.get("/history?page=1&page_size=100");
        const items = res.data.items || [];
        let uploads = items.length;
        let urls = 0;
        let malicious = 0;
        const attackTypesSet = new Set();
        
        for (const item of items) {
          urls += item.total_urls || 0;
          malicious += item.malicious_count || 0;
          
          // Try to get attack type breakdown
          try {
            const resultRes = await api.get(`/results/${item.upload_id}`);
            const results = resultRes.data.results || [];
            
            for (const result of results) {
              if (result.is_malicious) {
                const attackType = result.attack_type || result.ml_attack_type || 'unknown';
                if (attackType !== 'benign') {
                  attackTypesSet.add(attackType);
                }
              }
            }
          } catch (e) {
            // Skip if can't fetch results
          }
        }
        
        setStats({ uploads, urls, malicious, attackTypes: attackTypesSet.size });
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
      <div className="text-center mb-8">
        <h1 className="text-3xl font-bold text-gray-900 mb-2">🛡️ URL Detector II</h1>
        <p className="text-lg text-gray-600">Enhanced Multiclass ML Cyber Attack Detection</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card title="Total Uploads" value={stats.uploads} />
        <Card title="Total URLs Parsed" value={stats.urls} />
        <Card title="Malicious URLs" value={stats.malicious} />
        <Card title="Attack Types Detected" value={stats.attackTypes} />
      </div>

      <div className="bg-white rounded-lg shadow p-6">
        <h2 className="text-xl font-semibold mb-4">🎯 Supported Attack Types</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          <div className="flex items-center space-x-2 p-2 bg-red-50 rounded">
            <span>💉</span>
            <span className="text-sm font-medium">SQL Injection</span>
          </div>
          <div className="flex items-center space-x-2 p-2 bg-orange-50 rounded">
            <span>🔗</span>
            <span className="text-sm font-medium">Cross-Site Scripting</span>
          </div>
          <div className="flex items-center space-x-2 p-2 bg-purple-50 rounded">
            <span>📁</span>
            <span className="text-sm font-medium">Directory Traversal</span>
          </div>
          <div className="flex items-center space-x-2 p-2 bg-red-50 rounded">
            <span>⚡</span>
            <span className="text-sm font-medium">Command Injection</span>
          </div>
          <div className="flex items-center space-x-2 p-2 bg-yellow-50 rounded">
            <span>🌐</span>
            <span className="text-sm font-medium">SSRF</span>
          </div>
          <div className="flex items-center space-x-2 p-2 bg-blue-50 rounded">
            <span>📄</span>
            <span className="text-sm font-medium">File Inclusion</span>
          </div>
          <div className="flex items-center space-x-2 p-2 bg-red-50 rounded">
            <span>🔨</span>
            <span className="text-sm font-medium">Brute Force</span>
          </div>
          <div className="flex items-center space-x-2 p-2 bg-pink-50 rounded">
            <span>🔀</span>
            <span className="text-sm font-medium">Parameter Pollution</span>
          </div>
          <div className="flex items-center space-x-2 p-2 bg-gray-50 rounded">
            <span>📋</span>
            <span className="text-sm font-medium">XXE</span>
          </div>
          <div className="flex items-center space-x-2 p-2 bg-red-50 rounded">
            <span>🐚</span>
            <span className="text-sm font-medium">Web Shell Upload</span>
          </div>
          <div className="flex items-center space-x-2 p-2 bg-blue-50 rounded">
            <span>🎭</span>
            <span className="text-sm font-medium">Typosquatting</span>
          </div>
        </div>
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
