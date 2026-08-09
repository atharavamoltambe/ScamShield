import React from "react";
import { ShieldCheck, ShieldAlert, AlertTriangle } from "lucide-react";

const CARD_THEMES = {
  high_risk: {
    class: "advice-high",
    title: "Critical Action Required",
    icon: ShieldAlert
  },
  caution: {
    class: "advice-caution",
    title: "Recommended Precautions",
    icon: AlertTriangle
  },
  safe: {
    class: "advice-safe",
    title: "Safe to Proceed",
    icon: ShieldCheck
  }
};

export default function ActionAdvice({ action, verdict }) {
  if (!action) return null;

  const theme = CARD_THEMES[verdict] || CARD_THEMES["safe"];
  const IconComponent = theme.icon;

  return (
    <div className={`action-advice-card card-shadow ${theme.class}`}>
      <div className="advice-header">
        <IconComponent size={20} className="advice-icon" />
        <span className="advice-title">{theme.title}</span>
      </div>
      <p className="advice-text">{action}</p>
    </div>
  );
}
