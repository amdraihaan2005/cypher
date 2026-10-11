import React, { memo } from 'react';
import { Plus, Trash2, MessageSquare, ChevronLeft, ChevronRight } from 'lucide-react';

const Sidebar = memo(function Sidebar({
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
          type="button"
          className="sidebar-toggle-btn"
          onClick={onToggle}
          title="Open Threads"
          aria-label="Open Threads"
          aria-expanded={false}
          aria-controls="threads-sidebar"
        >
          <ChevronRight size={18} />
        </button>
      )}

      <aside
        id="threads-sidebar"
        className={`sidebar ${isOpen ? '' : 'collapsed'}`}
        aria-label="Conversation Threads"
      >
        <div className="sidebar-header">
          <span className="sidebar-title">Threads</span>
          <button
            type="button"
            onClick={onToggle}
            className="modal-close-btn"
            title="Collapse Sidebar"
            aria-label="Collapse Sidebar"
            aria-expanded={true}
          >
            <ChevronLeft size={18} />
          </button>
        </div>

        <button type="button" className="new-query-btn" onClick={onNewThread}>
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
                  type="button"
                  className="history-delete-btn"
                  onClick={(e) => {
                    e.stopPropagation();
                    onDeleteThread(thread.id);
                  }}
                  title="Delete thread"
                  aria-label={`Delete thread: ${thread.title}`}
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
              type="button"
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
});

export default Sidebar;
