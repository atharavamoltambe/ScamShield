import React from "react";

export default function RiskScore({ score, verdict }) {
  // Enforce score bounds between 0 and 100
  const cleanScore = Math.max(0, Math.min(100, score || 0));
  
  const getProgressColor = () => {
    switch (verdict) {
      case "high_risk":
        return "progress-red";
      case "caution":
        return "progress-amber";
      case "safe":
      default:
        return "progress-green";
    }
  };

  return (
    <div className="risk-score-wrapper">
      <div className="score-header">
        <span className="score-value">{cleanScore}</span>
        <span className="score-total">/ 100</span>
      </div>
      <span className="score-label">Risk Score</span>
      
      <div className="risk-bar-container">
        <div 
          className={`risk-bar-fill ${getProgressColor()}`}
          style={{ width: `${cleanScore}%` }}
          role="progressbar"
          aria-valuenow={cleanScore}
          aria-valuemin="0"
          aria-valuemax="100"
        />
      </div>
    </div>
  );
}
