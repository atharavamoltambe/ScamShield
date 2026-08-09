import React from "react";
import { AlertTriangle, RefreshCw, Loader, Clock } from "lucide-react";

// Helper to format ISO timestamp as "time ago"
function timeAgo(dateString) {
  if (!dateString) return "";
  try {
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now - date;
    const diffSec = Math.floor(diffMs / 1000);
    const diffMin = Math.floor(diffSec / 60);
    const diffHr = Math.floor(diffMin / 60);
    const diffDay = Math.floor(diffHr / 24);

    if (diffSec < 60) return "Just now";
    if (diffMin < 60) return `${diffMin}m ago`;
    if (diffHr < 24) return `${diffHr}h ago`;
    return `${diffDay}d ago`;
  } catch {
    return "Recent";
  }
}

// Helper to safely truncate messages
function truncateMessage(text, maxLength = 80) {
  if (!text) return "";
  if (text.length <= maxLength) return text;
  return text.slice(0, maxLength) + "...";
}

export default function RecentReports({ reports = [], loading, onRefresh, onSelectReport }) {
  const hasReports = reports && reports.length > 0;

  return (
    <section id="recent-scams" className="recent-reports-section">
      <div className="section-header-row">
        <div>
          <h2 className="section-main-title">Recently Reported Scams</h2>
          <p className="section-subtitle">
            Examples of suspicious messages reported to Scam Shield. Click on any scam to view its detailed threat analysis.
          </p>
        </div>
        
        <button
          type="button"
          className={`refresh-button-pill ${loading ? "spinning" : ""}`}
          onClick={onRefresh}
          disabled={loading}
          aria-label="Refresh scam reports"
        >
          {loading ? (
            <Loader size={16} className="animate-spin" />
          ) : (
            <RefreshCw size={16} />
          )}
          <span>Refresh</span>
        </button>
      </div>

      {loading && reports.length === 0 ? (
        <div className="reports-loading-box">
          <Loader size={24} className="animate-spin text-primary" />
          <p>Loading recent reports...</p>
        </div>
      ) : !hasReports ? (
        <div className="reports-empty-box">
          <Clock size={32} className="empty-icon" />
          <p className="empty-text">Nobody has reported a scam yet.</p>
        </div>
      ) : (
        <div className="reports-grid">
          {reports.map((report, index) => (
            <div 
              key={index} 
              className="report-card card-shadow cursor-pointer"
              onClick={() => onSelectReport && onSelectReport(report)}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => {
                if ((e.key === "Enter" || e.key === " ") && onSelectReport) {
                  e.preventDefault();
                  onSelectReport(report);
                }
              }}
              aria-label={`View details of reported scam: ${truncateMessage(report.text, 40)}`}
            >
              <div className="report-card-header">
                <div className="report-badge">
                  <AlertTriangle size={14} className="badge-icon" />
                  <span>Reported Scam</span>
                </div>
                <span className="report-time">{timeAgo(report.timestamp)}</span>
              </div>
              
              <p className="report-text-content">
                "{truncateMessage(report.text)}"
              </p>
              
              {report.notes && (
                <div className="report-notes-block">
                  <span className="notes-label">Note:</span>
                  <span className="notes-content">{report.notes}</span>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
