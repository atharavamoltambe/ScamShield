import React from "react";
import { Shield } from "lucide-react";

export default function Footer() {
  const currentYear = new Date().getFullYear();

  return (
    <footer className="app-footer">
      <div className="footer-container">
        <div className="footer-brand">
          <div className="footer-logo">
            <Shield size={20} className="footer-logo-icon" />
            <span className="footer-brand-name">Scam Shield</span>
          </div>
          <p className="footer-tagline">Check before you click.</p>
        </div>
        
        <div className="footer-disclaimer-box">
          <span className="disclaimer-title">Disclaimer</span>
          <p className="disclaimer-text">
            Scam Shield is an awareness and decision-support tool. Always verify 
            important requests through official channels. Scam Shield does not 
            guarantee absolute safety from all threats.
          </p>
        </div>
      </div>
      
      <div className="footer-copyright">
        <p>&copy; {currentYear} Scam Shield. All rights reserved.</p>
      </div>
    </footer>
  );
}
