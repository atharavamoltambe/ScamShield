import React from "react";
import { Shield, ShieldAlert, Activity } from "lucide-react";

export default function Header({ apiOnline }) {
  const handleScroll = (id) => {
    const element = document.getElementById(id);
    if (element) {
      element.scrollIntoView({ behavior: "smooth" });
    }
  };

  return (
    <header className="app-header">
      <div className="header-container">
        <div className="header-logo" onClick={() => window.scrollTo({ top: 0, behavior: "smooth" })}>
          <Shield className="logo-icon" size={24} />
          <span className="logo-text">Scam Shield</span>
        </div>
        
        <nav className="header-nav">
          <button onClick={() => handleScroll("how-it-works")} className="nav-link">
            How it Works
          </button>
          <button onClick={() => handleScroll("recent-scams")} className="nav-link">
            Recent Scams
          </button>
          <button onClick={() => handleScroll("behind-the-shield")} className="nav-link">
            Technology
          </button>
          
          <div className={`health-badge ${apiOnline ? "online" : "offline"}`}>
            <span className="status-dot"></span>
            <span className="status-text">{apiOnline ? "API Active" : "API Offline"}</span>
          </div>
        </nav>
      </div>
    </header>
  );
}
