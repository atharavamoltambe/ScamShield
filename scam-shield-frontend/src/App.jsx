import React, { useState, useEffect, useRef } from "react";
import Header from "./components/Header";
import Hero from "./components/Hero";
import MessageChecker from "./components/MessageChecker";
import ExampleMessages from "./components/ExampleMessages";
import ResultCard from "./components/ResultCard";
import Indicators from "./components/Indicators";
import URLAnalysis from "./components/URLAnalysis";
import AIExplanation from "./components/AIExplanation";
import ActionAdvice from "./components/ActionAdvice";
import ReportButton from "./components/ReportButton";
import RecentReports from "./components/RecentReports";
import HowItWorks from "./components/HowItWorks";
import Footer from "./components/Footer";
import { checkMessage, getReports, getHealth } from "./services/api";
import { AlertCircle, Loader } from "lucide-react";

export default function App() {
  // Input and General State
  const [message, setMessage] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);
  
  // Backend Health State
  const [apiOnline, setApiOnline] = useState(true);

  // Reports Feed State
  const [reports, setReports] = useState([]);
  const [reportsLoading, setReportsLoading] = useState(false);

  const resultRef = useRef(null);

  // Initial Load: check health and retrieve reports feed
  useEffect(() => {
    fetchHealthStatus();
    fetchReportsFeed();
  }, []);

  const fetchHealthStatus = async () => {
    try {
      const health = await getHealth();
      setApiOnline(health && health.status === "ok");
    } catch {
      setApiOnline(false);
    }
  };

  const fetchReportsFeed = async () => {
    setReportsLoading(true);
    try {
      const data = await getReports();
      setReports(data || []);
    } catch (err) {
      console.error("Failed to load recent reports:", err);
    } finally {
      setReportsLoading(false);
    }
  };

  const handleCheck = async (textToCheck) => {
    setLoading(true);
    setError(null);
    
    try {
      const response = await checkMessage(textToCheck);
      setResult(response);
      setApiOnline(true);
      
      // Smooth scroll to the result block after rendering
      setTimeout(() => {
        if (resultRef.current) {
          resultRef.current.scrollIntoView({ behavior: "smooth" });
        }
      }, 100);
    } catch (err) {
      console.error("Error during message analysis:", err);
      setResult(null);
      setApiOnline(false);
      setError(
        "Unable to connect to Scam Shield. Make sure the FastAPI backend is running at http://127.0.0.1:8000."
      );
    } finally {
      setLoading(false);
    }
  };

  const handleClear = () => {
    setMessage("");
    setResult(null);
    setError(null);
  };

  const handleExampleSelect = (exampleText) => {
    setMessage(exampleText);
    // Don't auto-submit so the user can review/edit
  };

  return (
    <div className="app-container">
      <Header apiOnline={apiOnline} />
      
      <main className="main-content">
        <Hero />
        
        {/* Input/Form Block */}
        <MessageChecker
          message={message}
          setMessage={setMessage}
          loading={loading}
          onCheck={handleCheck}
          onClear={handleClear}
        />
        
        <ExampleMessages onSelectExample={handleExampleSelect} />

        {/* Loading Indicator */}
        {loading && (
          <div className="loading-indicator-box">
            <Loader size={36} className="loading-spinner" />
            <p className="loading-text">Analyzing message...</p>
            <p className="loading-subtext">Resolving links and processing indicators...</p>
          </div>
        )}

        {/* Error Cards */}
        {error && (
          <div className="error-card card-shadow" role="alert">
            <div className="error-title">Unable to connect to Scam Shield</div>
            <p className="error-desc">{error}</p>
            <button 
              type="button" 
              className="retry-button"
              onClick={() => handleCheck(message)}
            >
              Try Again
            </button>
          </div>
        )}

        {/* Result Dashboard */}
        {result && !loading && (
          <section ref={resultRef} className="result-section">
            <h2 className="result-section-title">Analysis Result</h2>
            
            <div className="dashboard-layout">
              {/* Left Column: Result Card and AI Explanations */}
              <div className="dashboard-column">
                <ResultCard result={result} />
                <AIExplanation 
                  explanation={result.explanation} 
                  ragContext={result.rag_context} 
                />
              </div>

              {/* Right Column: Flags, Links, Action, and Reporting */}
              <div className="dashboard-column">
                <ActionAdvice 
                  action={result.action} 
                  verdict={result.verdict} 
                />
                
                <Indicators 
                  indicators={result.indicators} 
                  reasons={result.reasons} 
                />
                
                <URLAnalysis urlAnalysis={result.url_analysis} />
                
                <ReportButton 
                  messageText={message} 
                  onReportSuccess={fetchReportsFeed} 
                />
              </div>
            </div>
          </section>
        )}

        <HowItWorks />
        
        <RecentReports
          reports={reports}
          loading={reportsLoading}
          onRefresh={fetchReportsFeed}
        />
      </main>
      
      <Footer />
    </div>
  );
}
