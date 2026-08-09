import React, { useState, useEffect } from "react";
import { X, AlertTriangle, ShieldAlert, Clock, RefreshCw } from "lucide-react";
import RiskScore from "./RiskScore";
import Indicators from "./Indicators";
import URLAnalysis from "./URLAnalysis";
import AIExplanation from "./AIExplanation";
import ActionAdvice from "./ActionAdvice";
import ResultCard from "./ResultCard";

export default function ReportDetailModal({ report, onClose, apiBaseUrl }) {
  const [analysis, setAnalysis] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchAnalysis = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch(`${apiBaseUrl}/api/check`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ text: report.text }),
      });

      if (!response.ok) {
        throw new Error("Failed to load details from the analysis server.");
      }

      const data = await response.json();
      setAnalysis(data);
    } catch (err) {
      setError(err.message || "Something went wrong.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (report && report.text) {
      fetchAnalysis();
    }
  }, [report]);

  if (!report) return null;

  return (
    <div className="detail-modal-overlay">
      <div className="detail-modal-container bg-white-card animate-slideUp">
        {/* Header */}
        <header className="detail-modal-header">
          <div className="header-meta">
            <span className="meta-badge">
              <ShieldAlert size={14} className="mr-1" />
              <span>Scam Investigation Report</span>
            </span>
            {report.timestamp && (
              <span className="meta-time">
                <Clock size={12} className="mr-1" />
                {new Date(report.timestamp).toLocaleString()}
              </span>
            )}
          </div>
          <button
            type="button"
            className="close-modal-button"
            onClick={onClose}
            aria-label="Go back"
          >
            <X size={20} className="mr-1" />
            <span>Close Report</span>
          </button>
        </header>

        {/* Content Area */}
        <main className="detail-modal-body">
          {/* Section 1: Raw message check */}
          <section className="detail-message-section card-shadow bg-white-card">
            <h4 className="detail-section-title">Reported Message Content</h4>
            <div className="raw-message-box">
              <p className="raw-message-text">"{report.text}"</p>
            </div>
            {report.notes && (
              <div className="raw-message-notes">
                <strong>Submitter Note:</strong> {report.notes}
              </div>
            )}
          </section>

          {/* Loading States */}
          {loading && (
            <div className="detail-loading-box">
              <RefreshCw size={36} className="animate-spin text-teal mr-2" />
              <div>
                <p className="detail-loading-title">Retrieving Scam Intelligence...</p>
                <p className="detail-loading-desc">Running safety patterns and checking indicators...</p>
              </div>
            </div>
          )}

          {/* Error States */}
          {error && (
            <div className="detail-error-box card-shadow">
              <AlertTriangle size={24} className="text-high mr-3" />
              <div>
                <h4 className="detail-error-title">Unable to fetch scam details</h4>
                <p className="detail-error-desc">{error}</p>
                <button
                  type="button"
                  className="retry-button mt-2"
                  onClick={fetchAnalysis}
                >
                  Retry Analysis
                </button>
              </div>
            </div>
          )}

          {/* Analysis Results Display */}
          {analysis && !loading && (
            <div className="detail-analysis-grid">
              {/* Left Side: Verdict & AI Explanations */}
              <div className="detail-grid-column">
                <ResultCard result={analysis} />
                
                <AIExplanation
                  explanation={analysis.explanation}
                  ragContext={analysis.rag_context}
                />
              </div>

              {/* Right Side: Indicators, URLs, Action Advice */}
              <div className="detail-grid-column">
                <ActionAdvice
                  action={analysis.action}
                  verdict={analysis.verdict}
                />

                <Indicators
                  indicators={analysis.indicators}
                  reasons={analysis.reasons}
                />

                <URLAnalysis urlAnalysis={analysis.url_analysis} />
              </div>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}
