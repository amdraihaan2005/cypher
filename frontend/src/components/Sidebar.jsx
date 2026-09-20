import React from 'react';
import { Plus, Trash2, MessageSquare, ChevronLeft, ChevronRight } from 'lucide-react';

export default function Sidebar({
  isOpen,
  onToggle,
  threads,
  activeThreadId,
  onSelectThread,
  onNewThread,
  onDeleteThread,
  onClearThreads,
}) {
  return (
    <>
      {/* Toggle button on the top left if collapsed */}
      {!isOpen && (
        <button
          className="sidebar-toggle-btn"
          onClick={onToggle}
          title="Open Threads"
          aria-label="Open Threads"
        >
          <ChevronRight size={18} />
        </button>
      )}

      <aside className={`sidebar ${isOpen ? '' : 'collapsed'}`}>
        <div className="sidebar-header">
          <span className="sidebar-title">Threads</span>
          <button
            onClick={onToggle}
            className="modal-close-btn"
            title="Collapse Sidebar"
            aria-label="Collapse Sidebar"
          >
            <ChevronLeft size={18} />
          </button>
        </div>

        <button className="new-query-btn" onClick={onNewThread}>
          <Plus size={16} />
          <span>New Thread</span>
        </button>

        <div className="history-list">
          {threads.length === 0 ? (
            <div style={{ padding: '24px 8px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '12px' }}>
              No active threads yet.
            </div>
          ) : (
            threads.map((thread) => (
              <div
                key={thread.id}
                className={`history-item ${activeThreadId === thread.id ? 'active' : ''}`}
                onClick={() => onSelectThread(thread)}
              >
                <MessageSquare size={13} style={{ marginRight: '8px', flexShrink: 0, opacity: 0.7 }} />
                <span className="history-query-text" title={thread.title}>
                  {thread.title}
                </span>
                <button
                  className="history-delete-btn"
                  onClick={(e) => {
                    e.stopPropagation();
                    onDeleteThread(thread.id);
                  }}
                  title="Delete thread"
                >
                  <Trash2 size={13} />
                </button>
              </div>
            ))
          )}
        </div>

        {threads.length > 0 && (
          <div className="sidebar-footer">
            <span>{threads.length} {threads.length === 1 ? 'thread' : 'threads'}</span>
            <button
              onClick={onClearThreads}
              style={{ color: 'var(--text-muted)', fontSize: '11px' }}
              onMouseEnter={(e) => (e.currentTarget.style.color = 'var(--danger)')}
              onMouseLeave={(e) => (e.currentTarget.style.color = 'var(--text-muted)')}
            >
              Clear All
            </button>
          </div>
        )}
      </aside>
    </>
  );
}
