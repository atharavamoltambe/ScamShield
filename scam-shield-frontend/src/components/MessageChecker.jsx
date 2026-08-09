import React, { useRef, useEffect } from "react";
import { Search, X, Loader } from "lucide-react";

export default function MessageChecker({ message, setMessage, loading, onCheck, onClear }) {
  const textareaRef = useRef(null);

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
    if (textareaRef.current) {
      textareaRef.current.focus();
    }
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!message.trim() || loading) return;
    onCheck(message);
  };

  const charCount = message.length;

  return (
    <form className="checker-form" onSubmit={handleSubmit}>
      <div className="textarea-wrapper">
        <label htmlFor="message-input" className="visually-hidden">
          WhatsApp or SMS message text to analyze
        </label>
        <textarea
          id="message-input"
          ref={textareaRef}
          className="message-textarea"
          placeholder="Paste your WhatsApp or SMS message here..."
          value={message}
          onChange={handleTextChange}
          disabled={loading}
          rows={4}
          maxLength={2000}
        />
        
        {message && !loading && (
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
          disabled={loading || !message.trim()}
        >
          {loading ? (
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
  );
}
