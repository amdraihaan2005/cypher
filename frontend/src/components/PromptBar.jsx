import React, { useRef, useEffect } from 'react';
import { ArrowUp } from 'lucide-react';

export default function PromptBar({ query, setQuery, onSubmit, loading }) {
  const textareaRef = useRef(null);

  useEffect(() => {
    if (textareaRef.current) {
      textareaRef.current.style.height = 'auto';
      textareaRef.current.style.height = `${Math.min(textareaRef.current.scrollHeight, 120)}px`;
    }
  }, [query]);

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      if (!loading && query.trim()) {
        onSubmit(query.trim());
      }
    }
  };

  return (
    <div className="prompt-box">
      <div className="prompt-input-row">
        <textarea
          ref={textareaRef}
          className="prompt-textarea"
          rows={1}
          placeholder="Ask any cybersecurity question, describe an attack, or enter a MITRE ID (e.g. T1003.001)..."
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={handleKeyDown}
        />
        <button
          className="submit-btn"
          disabled={loading || !query.trim()}
          onClick={() => {
            if (!loading && query.trim()) {
              onSubmit(query.trim());
            }
          }}
          title="Run MITRE Intelligence Analysis"
          aria-label="Run analysis"
        >
          {loading ? (
            <div className="spinner" style={{ width: '14px', height: '14px', borderWidth: '2px' }} />
          ) : (
            <ArrowUp size={18} />
          )}
        </button>
      </div>
    </div>
  );
}
