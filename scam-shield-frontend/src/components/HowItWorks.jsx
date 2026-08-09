import React from "react";
import { Clipboard, BrainCircuit, BookOpen, ShieldCheck, Cpu, Link, FileSearch, Sparkles } from "lucide-react";

export default function HowItWorks() {
  return (
    <section id="how-it-works" className="how-it-works-section">
      <div className="section-header">
        <h2 className="section-main-title">How Scam Shield Works</h2>
        <p className="section-subtitle">
          An overview of the multi-layered analysis pipeline running under the hood.
        </p>
      </div>

      <div className="steps-grid">
        <div className="step-card card-shadow">
          <div className="step-number">01</div>
          <div className="step-icon-wrapper">
            <Clipboard size={20} className="step-icon" />
          </div>
          <h3 className="step-title">Paste</h3>
          <p className="step-text">Paste the suspicious WhatsApp/SMS message into the checker.</p>
        </div>

        <div className="step-card card-shadow">
          <div className="step-number">02</div>
          <div className="step-icon-wrapper">
            <BrainCircuit size={20} className="step-icon" />
          </div>
          <h3 className="step-title">Analyze</h3>
          <p className="step-text">Scam Shield checks files, URLs, keywords, urgency and scam patterns.</p>
        </div>

        <div className="step-card card-shadow">
          <div className="step-number">03</div>
          <div className="step-icon-wrapper">
            <BookOpen size={20} className="step-icon" />
          </div>
          <h3 className="step-title">Understand</h3>
          <p className="step-text">RAG retrieves relevant trusted scam knowledge from the database.</p>
        </div>

        <div className="step-card card-shadow">
          <div className="step-number">04</div>
          <div className="step-icon-wrapper">
            <ShieldCheck size={20} className="step-icon" />
          </div>
          <h3 className="step-title">Decide</h3>
          <p className="step-text">The system explains the risk clearly so you can decide before clicking.</p>
        </div>
      </div>

      {/* Technology Pipeline Section */}
      <div id="behind-the-shield" className="technology-pipeline-box card-shadow">
        <h3 className="pipeline-title">Behind the Shield</h3>
        <p className="pipeline-disclaimer">
          <strong>Note:</strong> Risk detection is performed by our deterministic security analysis engine. 
          AI is used exclusively to explain the result.
        </p>

        <div className="pipeline-visual-flow">
          <div className="pipeline-node">
            <div className="node-icon-box bg-purple">
              <Cpu size={18} />
            </div>
            <span className="node-label">Rule Engine</span>
            <p className="node-desc">Detects known scam indicators & keywords.</p>
          </div>
          
          <div className="pipeline-connector">→</div>

          <div className="pipeline-node">
            <div className="node-icon-box bg-blue">
              <Link size={18} />
            </div>
            <span className="node-label">URL & Domain Analysis</span>
            <p className="node-desc">Checks suspicious links and look-alike domains.</p>
          </div>

          <div className="pipeline-connector">→</div>

          <div className="pipeline-node">
            <div className="node-icon-box bg-green">
              <FileSearch size={18} />
            </div>
            <span className="node-label">RAG Knowledge Retrieval</span>
            <p className="node-desc">Retrieves relevant trusted scam templates.</p>
          </div>

          <div className="pipeline-connector">→</div>

          <div className="pipeline-node">
            <div className="node-icon-box bg-ai">
              <Sparkles size={18} />
            </div>
            <span className="node-label">AI Explanation</span>
            <p className="node-desc">Explains the detected risks in simple language.</p>
          </div>
        </div>
      </div>
    </section>
  );
}
