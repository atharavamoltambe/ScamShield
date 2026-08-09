import React from "react";
import { Link2, AlertTriangle, HelpCircle, CheckCircle } from "lucide-react";

export default function URLAnalysis({ urlAnalysis }) {
  if (!urlAnalysis || !urlAnalysis.found || !urlAnalysis.urls || urlAnalysis.urls.length === 0) {
    return null;
  }

  const getStatusIcon = (status) => {
    switch (status) {
      case "suspicious":
        return <AlertTriangle size={16} className="url-status-icon icon-suspicious" />;
      case "safe":
        return <CheckCircle size={16} className="url-status-icon icon-safe" />;
      case "neutral":
      default:
        return <HelpCircle size={16} className="url-status-icon icon-neutral" />;
    }
  };

  return (
    <div className="url-analysis-section card-shadow bg-white-card">
      <h3 className="section-title">
        <Link2 className="title-icon" size={18} />
        <span>Link Analysis</span>
      </h3>
      
      <div className="url-list">
        {urlAnalysis.urls.map((urlItem, index) => {
          const isSuspicious = urlItem.status === "suspicious";
          return (
            <div 
              key={index} 
              className={`url-item-card ${isSuspicious ? "border-suspicious" : "border-neutral"}`}
            >
              <div className="url-meta-header">
                <span className="url-domain-label">{urlItem.domain || "Unknown Domain"}</span>
                <div className="url-status-badge">
                  {getStatusIcon(urlItem.status)}
                  <span className={`status-text-label status-${urlItem.status}`}>
                    {urlItem.status ? urlItem.status.toUpperCase() : "UNKNOWN"}
                  </span>
                </div>
              </div>

              {/* Displaying raw text, no <a> tag to prevent clicking */}
              <div className="url-raw-display">
                <span className="raw-url-text">{urlItem.url}</span>
              </div>

              {urlItem.reason && (
                <div className="url-reason-block">
                  <span className="reason-label">Verdict Reason:</span>
                  <span className="reason-content-text">{urlItem.reason}</span>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
