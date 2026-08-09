import React from "react";
import { AlertCircle, ShieldAlert, Check } from "lucide-react";

export default function Indicators({ indicators = [], reasons = [] }) {
  const hasIndicators = indicators && indicators.length > 0;
  const hasReasons = reasons && reasons.length > 0;

  return (
    <div className="indicators-section card-shadow bg-white-card">
      <h3 className="section-title">
        <ShieldAlert className="title-icon" size={18} />
        <span>Why we flagged this</span>
      </h3>
      
      {hasIndicators ? (
        <ul className="indicators-list">
          {indicators.map((ind, index) => (
            <li key={index} className="indicator-item">
              <span className="indicator-check">✓</span>
              <span className="indicator-text">{ind}</span>
            </li>
          ))}
        </ul>
      ) : (
        <p className="no-indicators-text">No specific indicators were detected.</p>
      )}

      {hasReasons && (
        <div className="detection-details">
          <span className="details-heading">Detection details:</span>
          <ul className="reasons-list">
            {reasons.map((reason, index) => (
              <li key={index} className="reason-item">
                <span className="bullet-point">•</span>
                <span className="reason-text">{reason}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
