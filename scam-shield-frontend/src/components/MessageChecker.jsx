import React, { useRef, useState, useEffect } from "react";
import { Search, X, Loader, Camera, AlertCircle, Trash2 } from "lucide-react";
import { analyzeScreenshot } from "../services/api";

export default function MessageChecker({ message, setMessage, loading, onCheck, onClear, onAnalysisResult }) {
  const textareaRef = useRef(null);
  const fileInputRef = useRef(null);
  
  // Local states for screenshot upload & OCR
  const [selectedFile, setSelectedFile] = useState(null);
  const [previewUrl, setPreviewUrl] = useState(null);
  const [ocrLoading, setOcrLoading] = useState(false);
  const [localError, setLocalError] = useState(null);
  const [extractedText, setExtractedText] = useState("");

  // Auto-resize height of textarea based on content
  useEffect(() => {
    if (textareaRef.current) {
      textareaRef.current.style.height = "auto";
      textareaRef.current.style.height = `${textareaRef.current.scrollHeight}px`;
    }
  }, [message]);

  const handleTextChange = (e) => {
    setMessage(e.target.value);
  };

  const handleClearClick = () => {
    onClear();
    setExtractedText("");
    setSelectedFile(null);
    if (previewUrl) {
      URL.revokeObjectURL(previewUrl);
      setPreviewUrl(null);
    }
    setLocalError(null);
    if (textareaRef.current) {
      textareaRef.current.focus();
    }
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!message.trim() || loading || ocrLoading) return;
    onCheck(message);
  };

  const handleFileChange = (e) => {
    const file = e.target.files[0];
    if (!file) return;

    // Validate type
    const validTypes = ["image/png", "image/jpeg", "image/jpg", "image/webp"];
    if (!validTypes.includes(file.type)) {
      setLocalError("Please upload a JPG, PNG, or WEBP screenshot.");
      return;
    }

    // Validate size (5MB)
    if (file.size > 5 * 1024 * 1024) {
      setLocalError("Screenshot is too large. Please upload a smaller image.");
      return;
    }

    setLocalError(null);
    setExtractedText("");
    setSelectedFile(file);

    // Create object URL for preview
    if (previewUrl) {
      URL.revokeObjectURL(previewUrl);
    }
    setPreviewUrl(URL.createObjectURL(file));
  };

  const handleRemoveFile = () => {
    setSelectedFile(null);
    if (previewUrl) {
      URL.revokeObjectURL(previewUrl);
      setPreviewUrl(null);
    }
    setLocalError(null);
    setExtractedText("");
    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }
  };

  const handleAnalyzeScreenshot = async () => {
    if (!selectedFile || ocrLoading || loading) return;

    setOcrLoading(true);
    setLocalError(null);
    setExtractedText("");

    try {
      const data = await analyzeScreenshot(selectedFile);
      setExtractedText(data.extracted_text);
      if (onAnalysisResult) {
        onAnalysisResult(data.analysis, data.extracted_text);
      }
    } catch (err) {
      setLocalError(err.message || "Unable to read this screenshot. Please try another image.");
    } finally {
      setOcrLoading(false);
    }
  };

  const charCount = message.length;

  return (
    <div className="message-checker-section card-shadow bg-white-card">
      <h3 className="section-title">Check a Suspicious Message</h3>
      <p className="section-subtitle">Paste a WhatsApp/SMS message or upload a screenshot to analyze threat indicators.</p>
      
      <form className="checker-form" onSubmit={handleSubmit}>
        <div className="textarea-wrapper">
          <label htmlFor="message-input" className="visually-hidden">
            WhatsApp or SMS message text to analyze
          </label>
          <textarea
            id="message-input"
            ref={textareaRef}
            className="message-textarea font-primary"
            placeholder="Paste suspicious message here..."
            value={message}
            onChange={handleTextChange}
            disabled={loading || ocrLoading}
            rows={4}
            maxLength={2000}
          />
          
          {message && !loading && !ocrLoading && (
            <button
              type="button"
              className="clear-button"
              onClick={handleClearClick}
              aria-label="Clear input"
            >
              <X size={18} />
            </button>
          )}
        </div>

        <div className="checker-footer">
          <span className="character-counter" aria-live="polite">
            {charCount} / 2000 characters
          </span>
          
          <button
            type="submit"
            className="submit-button"
            disabled={loading || ocrLoading || !message.trim()}
          >
            {loading && !ocrLoading ? (
              <>
                <Loader size={18} className="animate-spin mr-2" />
                <span>Analyzing...</span>
              </>
            ) : (
              <>
                <Search size={18} className="mr-2" />
                <span>Check Message</span>
              </>
            )}
          </button>
        </div>
      </form>

      {/* Screenshot Upload Block */}
      <div className="checker-or-divider">
        <span className="divider-line"></span>
        <span className="divider-text">OR</span>
        <span className="divider-line"></span>
      </div>

      <div className="screenshot-upload-area">
        <input
          type="file"
          ref={fileInputRef}
          onChange={handleFileChange}
          accept="image/png,image/jpeg,image/webp"
          style={{ display: "none" }}
        />
        
        {!selectedFile && (
          <div className="upload-button-wrapper">
            <button
              type="button"
              className="upload-screenshot-btn"
              onClick={() => fileInputRef.current?.click()}
              disabled={loading || ocrLoading}
            >
              <Camera size={18} className="mr-2" />
              <span>📷 Upload Screenshot</span>
            </button>
            <p className="privacy-note">
              Tip: Avoid uploading screenshots containing passwords, OTP codes, banking credentials, or other sensitive information.
            </p>
          </div>
        )}

        {/* Selected File Details & Preview */}
        {selectedFile && (
          <div className="preview-container card-shadow">
            <div className="preview-header">
              <span className="preview-status-label">Screenshot selected</span>
              <button
                type="button"
                className="remove-preview-btn"
                onClick={handleRemoveFile}
                disabled={ocrLoading}
              >
                <Trash2 size={14} className="mr-1" />
                <span>Remove</span>
              </button>
            </div>
            
            <div className="preview-display">
              {previewUrl && (
                <img
                  src={previewUrl}
                  alt="Selected message upload preview"
                  className="preview-image"
                />
              )}
              <div className="file-info-block">
                <span className="file-name-txt">{selectedFile.name}</span>
                <span className="file-size-txt">({(selectedFile.size / 1024).toFixed(1)} KB)</span>
              </div>
            </div>

            {!extractedText && (
              <button
                type="button"
                className="analyze-screenshot-btn"
                onClick={handleAnalyzeScreenshot}
                disabled={loading || ocrLoading}
              >
                {ocrLoading ? (
                  <>
                    <Loader size={16} className="animate-spin mr-2" />
                    <span>Analyzing Screenshot...</span>
                  </>
                ) : (
                  <span>Analyze Screenshot</span>
                )}
              </button>
            )}
          </div>
        )}

        {/* Loading Spinner for OCR */}
        {ocrLoading && (
          <div className="ocr-status-loader-box">
            <Loader size={28} className="animate-spin text-teal mr-3" />
            <div>
              <p className="status-title">📷 Analyzing screenshot...</p>
              <p className="status-subtitle">Extracting text and checking for scam indicators.</p>
            </div>
          </div>
        )}

        {/* Errors displaying */}
        {localError && (
          <div className="ocr-error-banner">
            <AlertCircle size={18} className="text-high mr-2 flex-shrink-0" />
            <span className="error-text">{localError}</span>
          </div>
        )}

        {/* Display Extracted Text */}
        {extractedText && (
          <div className="extracted-text-panel">
            <h4 className="extracted-header">Text detected from screenshot</h4>
            <div className="extracted-content-box">
              <p className="extracted-body-txt font-mono">"{extractedText}"</p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
