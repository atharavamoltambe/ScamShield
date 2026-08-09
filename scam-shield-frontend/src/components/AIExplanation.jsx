import React, { useState } from "react";
import { Sparkles, HelpCircle, ChevronDown, ChevronUp, BookOpen, AlertTriangle, CheckSquare } from "lucide-react";

export default function AIExplanation({ explanation, ragContext }) {
  const [ragExpanded, setRagExpanded] = useState(false);

  if (!explanation) {
    return (
      <div className="explanation-section card-shadow bg-white-card">
        <h3 className="section-title">
          <Sparkles className="title-icon text-ai" size={18} />
          <span>AI Explanation</span>
        </h3>
        <p className="fallback-explanation-text">
          An explanation could not be generated, but the risk analysis is still available.
        </p>
      </div>
    );
  }

  const { summary, why_risky = [], what_to_do = [], technical_explanation } = explanation;
  const hasRag = ragContext && ragContext.length > 0;

  return (
    <div className="explanation-section card-shadow bg-white-card">
      <div className="explanation-header">
        <Sparkles className="header-icon-ai animate-pulse" size={20} />
        <div>
          <h3 className="explanation-title">AI Explanation</h3>
          <span className="explanation-subtitle">Why Scam Shield reached this conclusion</span>
        </div>
      </div>

      <div className="explanation-body">
        {summary && <p className="explanation-summary">{summary}</p>}

        {why_risky.length > 0 && (
          <div className="explanation-block">
            <span className="block-label text-warning-strong">
              <AlertTriangle size={14} className="block-icon" />
              <span>Why is this suspicious?</span>
            </span>
            <ul className="explanation-list">
              {why_risky.map((item, index) => (
                <li key={index} className="explanation-item-text">{item}</li>
              ))}
            </ul>
          </div>
        )}

        {what_to_do.length > 0 && (
          <div className="explanation-block">
            <span className="block-label text-safe-strong">
              <CheckSquare size={14} className="block-icon" />
              <span>What should you do?</span>
            </span>
            <ul className="explanation-list">
              {what_to_do.map((item, index) => (
                <li key={index} className="explanation-item-text">{item}</li>
              ))}
            </ul>
          </div>
        )}

        {technical_explanation && (
          <div className="explanation-technical">
            <span className="technical-label">Technical Explanation:</span>
            <p className="technical-content">{technical_explanation}</p>
          </div>
        )}
      </div>

      {hasRag && (
        <div className="rag-expandable">
          <button 
            type="button"
            className="rag-toggle-button"
            onClick={() => setRagExpanded(!ragExpanded)}
            aria-expanded={ragExpanded}
          >
            <BookOpen size={16} className="toggle-icon-left" />
            <span className="toggle-text">Why this pattern is commonly used (RAG Context)</span>
            {ragExpanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
          </button>
          
          {ragExpanded && (
            <div className="rag-content-box">
              <p className="rag-intro-text">
                The analysis engine retrieved the following context about these tactics:
              </p>
              <ul className="rag-list">
                {ragContext.map((chunk, index) => (
                  <li key={index} className="rag-chunk-item">
                    {chunk}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
