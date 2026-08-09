import React from "react";
import { ShieldCheck } from "lucide-react";

export default function Hero() {
  return (
    <section className="hero-section">
      <div className="hero-badge">
        <ShieldCheck size={16} className="hero-badge-icon" />
        <span>Analyze first. Click later.</span>
      </div>
      <h1 className="hero-title">Check before you click.</h1>
      <p className="hero-subtitle">
        Paste a suspicious WhatsApp or SMS message and Scam Shield will analyze 
        the links, files, urgency signals, and scam patterns before you interact with them.
      </p>
    </section>
  );
}
