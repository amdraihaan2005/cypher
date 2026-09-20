import React from 'react';
import { User, Shield } from 'lucide-react';
import AnalysisResult from './AnalysisResult';

export default function ThreadMessage({ message, onSelectEntity }) {
  if (message.role === 'user') {
    return (
      <div className="thread-user-row">
        <div className="thread-user-bubble">
          <div className="thread-user-text">{message.content}</div>
        </div>
        <div className="thread-user-avatar" title="You">
          <User size={15} />
        </div>
      </div>
    );
  }

  // Assistant Message
  return (
    <div className="thread-assistant-row">
      <div className="thread-assistant-avatar" title="Cypher AI">
        <Shield size={16} />
      </div>
      <div className="thread-assistant-content">
        {message.loading ? (
          <div className="assistant-loading-box">
            <div className="spinner" style={{ width: '16px', height: '16px' }} />
            <span>Analyzing MITRE ATT&amp;CK knowledge graph with {message.model || 'openai/gpt-oss-120b'}...</span>
          </div>
        ) : message.error ? (
          <div className="assistant-error-box">
            <span>{message.error}</span>
          </div>
        ) : (
          <AnalysisResult
            report={message.report}
            onSelectEntity={onSelectEntity}
          />
        )}
      </div>
    </div>
  );
}
