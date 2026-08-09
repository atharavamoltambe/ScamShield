import React, { useState } from "react";
import { AlertTriangle, ChevronDown, ChevronUp, ShieldAlert, Sparkles } from "lucide-react";

// Map categories to visual emojis as required
const CATEGORY_ICONS = {
  file_risk: "📦",
  link_risk: "🔗",
  urgency: "⏰",
  payment: "💸",
  credential: "🔑",
  impersonation: "👤",
  scam_language: "📝",
  forwarded_urgency: "🔄"
};

export default function RiskBreakdown({ riskBreakdown = [], strongestWarning, verdict }) {
  const [expandedStates, setExpandedStates] = useState({});

  const toggleExpand = (index) => {
    setExpandedStates((prev) => ({
      ...prev,
      [index]: !prev[index]
    }));
  };

  const isSafe = verdict === "safe" || riskBreakdown.length === 0;

  return (
    <div className="risk-breakdown-card card-shadow bg-white-card">
      <div className="breakdown-header">
        <h3 className="breakdown-title">Risk Breakdown</h3>
        <p className="breakdown-subtitle">Why did Scam Shield give this score?</p>
      </div>

      {isSafe ? (
        <div className="safe-breakdown-message">
          <p className="safe-breakdown-text">No significant risk indicators were detected.</p>
        </div>
      ) : (
        <div className="breakdown-list">
          {riskBreakdown.map((item, index) => {
            const isExpanded = !!expandedStates[index];
            const icon = CATEGORY_ICONS[item.category] || "🚨";
            
            // Normalize visual bar relative to 40 (highest single weight in the engine)
            const barWidth = `${Math.min((item.points / 40) * 100, 100)}%`;
            
            // Set severity color class
            const severityClass = `severity-bar-${item.severity || "low"}`;

            return (
              <div key={index} className="breakdown-row-wrapper">
                <button
                  type="button"
                  className="breakdown-row-trigger"
                  onClick={() => toggleExpand(index)}
                  aria-expanded={isExpanded}
                >
                  <div className="row-main-info">
                    <span className="row-icon" role="img" aria-label={item.factor}>
                      {icon}
                    </span>
                    <span className="row-factor-name">{item.factor}</span>
                  </div>
                  <div className="row-points-block">
                    <span className={`row-points-badge points-badge-${item.severity}`}>
                      +{item.points}
                    </span>
                    {isExpanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                  </div>
                </button>

                {/* Progress bar representing weight */}
                <div className="breakdown-progress-track">
                  <div 
                    className={`breakdown-progress-bar ${severityClass}`} 
                    style={{ width: barWidth }} 
                  />
                </div>

                {/* Collapsible explanation block */}
                {isExpanded && (
                  <div className="breakdown-explanation-box animate-fadeIn">
                    <span className="explanation-caption-label">Why this matters:</span>
                    <p className="explanation-paragraph-text">{item.explanation}</p>
                  </div>
                )}
              </div>
            );
          })}

          {/* Strongest Warning display */}
          {strongestWarning && (
            <div className="strongest-warning-panel">
              <div className="strongest-warning-alert-row">
                <AlertTriangle size={16} className="text-high mr-2 animate-bounce" />
                <span className="strongest-warning-title">Strongest warning</span>
              </div>
              <h4 className="strongest-warning-factor">{strongestWarning.factor}</h4>
              <p className="strongest-warning-message">"{strongestWarning.message}"</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
