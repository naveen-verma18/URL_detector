import React from "react";
import { BrowserRouter, Routes, Route, Link, NavLink } from "react-router-dom";
import Home from "./pages/Home.jsx";
import Upload from "./pages/Upload.jsx";
import Results from "./pages/Results.jsx";
import Dashboard from "./pages/Dashboard.jsx";

function NavItem({ to, label }) {
  return (
    <NavLink
      to={to}
      className={({ isActive }) =>
        `px-3 py-2 rounded-md text-sm font-medium ${
          isActive ? "bg-blue-600 text-white" : "text-blue-700 hover:bg-blue-100"
        }`
      }
      end
    >
      {label}
    </NavLink>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <div className="min-h-screen flex flex-col">
        <header className="bg-white shadow">
          <div className="mx-auto max-w-7xl px-4 py-4 flex items-center justify-between">
            <Link to="/" className="text-xl font-bold text-blue-700">
              URL Detector II
            </Link>
            <nav className="space-x-2">
              <NavItem to="/" label="Home" />
              <NavItem to="/upload" label="Upload" />
              <NavItem to="/dashboard" label="Dashboard" />
            </nav>
          </div>
        </header>

        <main className="flex-1 mx-auto max-w-7xl w-full px-4 py-6">
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/upload" element={<Upload />} />
            <Route path="/results/:uploadId" element={<Results />} />
            <Route path="/dashboard" element={<Dashboard />} />
          </Routes>
        </main>

        <footer className="bg-white border-t">
          <div className="mx-auto max-w-7xl px-4 py-4 text-sm text-gray-600">
            © {new Date().getFullYear()} URL Detector II
          </div>
        </footer>
      </div>
    </BrowserRouter>
  );
}
