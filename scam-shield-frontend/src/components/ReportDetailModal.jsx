import React, { useState, useEffect } from "react";
import { X, ShieldAlert, Clock, RefreshCw, AlertTriangle, CheckCircle2, ShieldAlert as AlertIcon, Search, Link as LinkIcon, BookOpen, Sparkles } from "lucide-react";

export default function ReportDetailModal({ report, onClose, apiBaseUrl }) {
  const [analysis, setAnalysis] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Generate a mock Case reference number based on the report text hash
  const getCaseRef = () => {
    if (!report || !report.text) return "CASE-REF-0000";
    let hash = 0;
    for (let i = 0; i < report.text.length; i++) {
      hash = report.text.charCodeAt(i) + ((hash << 5) - hash);
    }
    const code = Math.abs(hash).toString(16).toUpperCase().slice(0, 4);
    return `SS-DOSSIER-${code}`;
  };

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

  const caseRef = getCaseRef();

  // Helper to format date
  const formatTime = (isoString) => {
    if (!isoString) return "";
    return new Date(isoString).toLocaleString("en-US", {
      dateStyle: "medium",
      timeStyle: "short",
    });
  };

  // Helper for severity color overrides
  const getSeverityClasses = (verdict) => {
    if (verdict === "high_risk") return { bg: "dossier-high", text: "text-high", label: "HIGH RISK" };
    if (verdict === "caution") return { bg: "dossier-caution", text: "text-caution", label: "CAUTION" };
    return { bg: "dossier-safe", text: "text-safe", label: "SAFE" };
  };

  return (
    <div className="dossier-overlay">
      <div className="dossier-container bg-white-card animate-slideUp">
        {/* Top bar */}
        <header className="dossier-header">
          <div className="dossier-title-block">
            <span className="case-id">{caseRef}</span>
            <h2 className="dossier-title">Threat Intelligence Dossier</h2>
          </div>
          <button
            type="button"
            className="dossier-close-button"
            onClick={onClose}
            aria-label="Close dossier"
          >
            <X size={18} className="mr-1" />
            <span>Close Dossier</span>
          </button>
        </header>

        {/* Content Area */}
        <div className="dossier-body">
          {/* Subheader Metadata */}
          <div className="dossier-metadata-bar">
            <div className="meta-item">
              <Clock size={14} className="mr-1" />
              <span>Reported: {formatTime(report.timestamp)}</span>
            </div>
            <div className="meta-item">
              <ShieldAlert size={14} className="mr-1" />
              <span>Status: Case Logged</span>
            </div>
          </div>

          {/* Loading Indicator */}
          {loading && (
            <div className="dossier-loading-box">
              <RefreshCw size={36} className="animate-spin text-teal mb-3" />
              <p className="dossier-loading-title">Decrypting Threat Patterns...</p>
              <p className="dossier-loading-desc">Executing full RTO & Banking forensics analysis...</p>
            </div>
          )}

          {/* Error Indicator */}
          {error && (
            <div className="dossier-error-box">
              <AlertTriangle size={24} className="text-high mr-3" />
              <div>
                <h4 className="dossier-error-title">Forensic Engine Timeout</h4>
                <p className="dossier-error-desc">{error}</p>
                <button
                  type="button"
                  className="retry-button mt-2"
                  onClick={fetchAnalysis}
                >
                  Re-initialize Audit
                </button>
              </div>
            </div>
          )}

          {/* Core Case Layout */}
          {analysis && !loading && (
            <div className="dossier-layout">
              
              {/* Verdict Summary Board */}
              <div className={`dossier-verdict-board ${getSeverityClasses(analysis.verdict).bg}`}>
                <div className="verdict-banner">
                  <div className="verdict-banner-left">
                    <span className="verdict-tag">System Verdict</span>
                    <h3 className="verdict-label-value">{getSeverityClasses(analysis.verdict).label}</h3>
                  </div>
                  <div className="verdict-score-box">
                    <span className="score-val">{analysis.score}</span>
                    <span className="score-max">/100</span>
                    <span className="score-desc">Risk Index</span>
                  </div>
                </div>

                <div className="metadata-table">
                  <div className="meta-row">
                    <span className="row-key">Scam Classification:</span>
                    <span className="row-val font-semibold">{analysis.category}</span>
                  </div>
                  <div className="meta-row">
                    <span className="row-key">Confidence Threshold:</span>
                    <span className="row-val font-semibold">{Math.round(analysis.confidence * 100)}%</span>
                  </div>
                  <div className="meta-row">
                    <span className="row-key">Analysis Source:</span>
                    <span className="row-val font-mono uppercase text-xs">{analysis.explanation_source} Layer</span>
                  </div>
                </div>
              </div>

              {/* Grid section */}
              <div className="dossier-grid">
                {/* Left Column: Evidence & AI explanation */}
                <div className="dossier-col">
                  {/* Evidence Block */}
                  <div className="dossier-section-card">
                    <h4 className="dossier-section-title">
                      <Search size={16} className="text-teal mr-2" />
                      <span>Captured Evidence Text</span>
                    </h4>
                    <div className="evidence-message-box">
                      <p className="evidence-text">"{report.text}"</p>
                    </div>
                    {report.notes && (
                      <div className="evidence-notes">
                        <strong>Log note:</strong> {report.notes}
                      </div>
                    )}
                  </div>

                  {/* AI Plain English Explanation */}
                  {analysis.explanation && (
                    <div className="dossier-section-card bg-neutral-light">
                      <h4 className="dossier-section-title text-ai">
                        <Sparkles size={16} className="mr-2" />
                        <span>Plain-English Briefing</span>
                      </h4>
                      <p className="dossier-briefing-summary">
                        {analysis.explanation.summary}
                      </p>

                      {analysis.explanation.why_risky && analysis.explanation.why_risky.length > 0 && (
                        <div className="briefing-group">
                          <span className="group-title text-high">Risks Identified:</span>
                          <ul className="briefing-ul">
                            {analysis.explanation.why_risky.map((pt, i) => (
                              <li key={i}>{pt}</li>
                            ))}
                          </ul>
                        </div>
                      )}

                      {analysis.explanation.what_to_do && analysis.explanation.what_to_do.length > 0 && (
                        <div className="briefing-group mt-3">
                          <span className="group-title text-safe">Action Plan:</span>
                          <ul className="briefing-ul">
                            {analysis.explanation.what_to_do.map((pt, i) => (
                              <li key={i}>{pt}</li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
                  )}
                </div>

                {/* Right Column: Signatures, URLs & Remediation */}
                <div className="dossier-col">
                  {/* Detected Signatures */}
                  <div className="dossier-section-card">
                    <h4 className="dossier-section-title">
                      <AlertTriangle size={16} className="text-warning mr-2" />
                      <span>Threat Signatures Audited</span>
                    </h4>
                    {analysis.indicators.length === 0 ? (
                      <p className="no-signatures">No critical security signatures matched by rule patterns.</p>
                    ) : (
                      <div className="signature-timeline">
                        {analysis.indicators.map((ind, idx) => (
                          <div key={idx} className="signature-item">
                            <div className="signature-dot" />
                            <div className="signature-content">
                              <span className="signature-name">{ind}</span>
                              {analysis.reasons[idx] && (
                                <p className="signature-desc">{analysis.reasons[idx]}</p>
                              )}
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* URL Forensic Analysis */}
                  {analysis.url_analysis && analysis.url_analysis.found && (
                    <div className="dossier-section-card">
                      <h4 className="dossier-section-title">
                        <LinkIcon size={16} className="text-teal mr-2" />
                        <span>Domain Investigations</span>
                      </h4>
                      <div className="dossier-url-list">
                        {analysis.url_analysis.urls.map((u, i) => (
                          <div key={i} className="dossier-url-item">
                            <div className="url-header-meta">
                              <span className="url-domain font-mono">{u.domain}</span>
                              <span className={`url-status-badge badge-${u.status}`}>
                                {u.status}
                              </span>
                            </div>
                            <p className="url-investigation-reason">{u.reason}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Remediation & Action Advice */}
                  <div className="dossier-section-card dossier-remediation-box">
                    <h4 className="dossier-section-title text-navy">
                      <CheckCircle2 size={16} className="mr-2" />
                      <span>Remediation Directives</span>
                    </h4>
                    <p className="remediation-text">{analysis.action}</p>
                  </div>
                </div>
              </div>

              {/* RAG Context Panel (Full Width) */}
              {analysis.rag_context && analysis.rag_context.length > 0 && (
                <div className="dossier-section-card dossier-rag-panel">
                  <h4 className="dossier-section-title text-navy">
                    <BookOpen size={16} className="mr-2" />
                    <span>Scam Vector Database Context (RAG Reference)</span>
                  </h4>
                  <div className="dossier-rag-content">
                    {analysis.rag_context.map((chunk, index) => (
                      <div key={index} className="dossier-rag-chunk">
                        <p className="rag-chunk-text font-mono text-xs">{chunk}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}

            </div>
          )}
        </div>
      </div>
    </div>
  );
}
