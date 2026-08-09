import React, { useState, useEffect } from "react";
import { AlertOctagon, CheckCircle2, Loader, AlertCircle } from "lucide-react";
import { reportScam } from "../services/api";

export default function ReportButton({ messageText, onReportSuccess }) {
  const [status, setStatus] = useState("idle"); // idle, loading, success, error

  // Reset state if the analyzed message changes
  useEffect(() => {
    setStatus("idle");
  }, [messageText]);

  const handleReport = async () => {
    if (!messageText || status === "loading" || status === "success") return;
    
    setStatus("loading");
    try {
      await reportScam(messageText, "Reported from Scam Shield checker");
      setStatus("success");
      if (onReportSuccess) {
        onReportSuccess();
      }
    } catch (err) {
      console.error("Failed to report scam:", err);
      setStatus("error");
    }
  };

  return (
    <div className="report-action-block">
      <button
        type="button"
        className={`report-button ${status}`}
        onClick={handleReport}
        disabled={status === "loading" || status === "success" || !messageText}
      >
        {status === "loading" && (
          <>
            <Loader size={16} className="animate-spin mr-2" />
            <span>Reporting...</span>
          </>
        )}
        {status === "success" && (
          <>
            <CheckCircle2 size={16} className="mr-2" />
            <span>Reported</span>
          </>
        )}
        {status === "idle" && (
          <>
            <AlertOctagon size={16} className="mr-2" />
            <span>Report this as a scam</span>
          </>
        )}
        {status === "error" && (
          <>
            <AlertCircle size={16} className="mr-2" />
            <span>Unable to submit report. Try again.</span>
          </>
        )}
      </button>

      {status === "success" && (
        <p className="report-confirmation-text" role="status">
          Thanks. This message has been added to the scam report feed.
        </p>
      )}
    </div>
  );
}
