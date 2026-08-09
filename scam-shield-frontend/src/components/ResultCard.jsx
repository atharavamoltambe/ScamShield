import React from "react";
import { ShieldCheck, ShieldAlert, ShieldAlert as ShieldWarning, Sparkles, Cpu } from "lucide-react";
import RiskScore from "./RiskScore";

const VERDICT_DETAILS = {
  high_risk: {
    label: "HIGH RISK",
    colorClass: "risk-high",
    icon: ShieldAlert,
    tagline: "Strong scam indicators detected. Avoid clicking links or downloading files."
  },
  caution: {
    label: "CAUTION",
    colorClass: "risk-caution",
    icon: ShieldWarning,
    tagline: "Suspicious indicators detected. Verify the sender before taking action."
  },
  safe: {
    label: "SAFE",
    colorClass: "risk-safe",
    icon: ShieldCheck,
    tagline: "No major indicators detected. Note that this does not guarantee absolute safety."
  }
};

export default function ResultCard({ result }) {
  const { verdict, score, category, confidence, explanation_source } = result;
  
  // Clean default mappings for safety
  const currentVerdict = VERDICT_DETAILS[verdict] || VERDICT_DETAILS["safe"];
  const IconComponent = currentVerdict.icon;

  const confidencePercentage = Math.round((confidence || 0) * 100);

  return (
    <div className={`result-card-container card-shadow ${currentVerdict.colorClass}`}>
      <div className="result-header">
        <div className="verdict-badge">
          <IconComponent size={24} className="verdict-icon" />
          <span className="verdict-label">{currentVerdict.label}</span>
        </div>
        <div className="source-badge">
          {explanation_source === "llm" ? (
            <>
              <Sparkles size={14} className="source-icon" />
              <span>AI-Assisted Explanation</span>
            </>
          ) : (
            <>
              <Cpu size={14} className="source-icon" />
              <span>Rule-Based Explanation</span>
            </>
          )}
        </div>
      </div>

      <div className="result-body-grid">
        <div className="result-score-block">
          <RiskScore score={score} verdict={verdict} />
        </div>
        
        <div className="result-info-block">
          <span className="info-title">Scam Category</span>
          <h2 className="info-category">{category || "General Phishing"}</h2>
          <p className="verdict-description">{currentVerdict.tagline}</p>
          
          {confidence !== undefined && (
            <div className="confidence-level">
              <span className="confidence-text">
                Analysis Confidence: <strong>{confidencePercentage}%</strong>
              </span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
