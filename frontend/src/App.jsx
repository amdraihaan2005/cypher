import React, { useState, useEffect, useRef } from 'react';
import TopLogo from './components/TopLogo';
import Sidebar from './components/Sidebar';
import PromptBar from './components/PromptBar';
import ThreadMessage from './components/ThreadMessage';
import EntityModal from './components/EntityModal';
import { analyzeThreat } from './api';
import { Shield } from 'lucide-react';

const STORAGE_KEY = 'cypher_ai_threads_v1';

export default function App() {
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [query, setQuery] = useState('');
  const [threads, setThreads] = useState([]);
  const [activeThreadId, setActiveThreadId] = useState(null);
  const [loading, setLoading] = useState(false);
  const [modalEntity, setModalEntity] = useState(null);
  const messagesEndRef = useRef(null);

  // Load threads from localStorage
  useEffect(() => {
    try {
      const saved = localStorage.getItem(STORAGE_KEY);
      if (saved) {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed)) {
          setThreads(parsed);
          if (parsed.length > 0) {
            setActiveThreadId(parsed[0].id);
          }
        }
      }
    } catch (e) {
      console.error('Failed to load threads from storage:', e);
    }
  }, []);

  const saveThreads = (newThreads) => {
    setThreads(newThreads);
    try {
      let data = JSON.stringify(newThreads);
      // Guard against hitting the ~5MB localStorage limit: prune oldest threads if over 4MB
      const MAX_BYTES = 4 * 1024 * 1024;
      let threads = newThreads;
      while (data.length > MAX_BYTES && threads.length > 1) {
        threads = threads.slice(0, -1); // drop oldest thread (last in array)
        data = JSON.stringify(threads);
      }
      localStorage.setItem(STORAGE_KEY, data);
    } catch (e) {
      console.error('Failed to save threads:', e);
    }
  };

  const activeThread = threads.find((t) => t.id === activeThreadId) || null;
  const messages = activeThread?.messages || [];

  // Scroll down to latest message
  useEffect(() => {
    if (messages.length > 0) {
      messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  }, [messages, loading]);

  const handleRunAnalysis = async (searchQuery) => {
    if (!searchQuery || !searchQuery.trim() || loading) return;

    const trimmed = searchQuery.trim();
    setQuery('');
    setLoading(true);

    const userMsg = {
      id: 'u-' + Date.now(),
      role: 'user',
      content: trimmed,
      timestamp: new Date().toISOString(),
    };

    const tempAssistantMsg = {
      id: 'a-' + Date.now(),
      role: 'assistant',
      loading: true,
      model: 'openai/gpt-oss-120b',
    };

    let targetThreadId = activeThreadId;
    let updatedThreads = [...threads];

    // If no active thread or thread not found, create a new one
    if (!targetThreadId || !threads.some((t) => t.id === targetThreadId)) {
      targetThreadId = Date.now().toString();
      const newThread = {
        id: targetThreadId,
        title: trimmed.length > 45 ? trimmed.slice(0, 45) + '...' : trimmed,
        createdAt: new Date().toISOString(),
        messages: [userMsg, tempAssistantMsg],
      };
      updatedThreads = [newThread, ...threads];
      setActiveThreadId(targetThreadId);
      saveThreads(updatedThreads);
    } else {
      // Append to active thread
      updatedThreads = threads.map((t) => {
        if (t.id === targetThreadId) {
          return {
            ...t,
            messages: [...t.messages, userMsg, tempAssistantMsg],
          };
        }
        return t;
      });
      saveThreads(updatedThreads);
    }

    try {
      // Gather previous completed messages strictly from the active thread being operated on
      const currentThread = updatedThreads.find((t) => t.id === targetThreadId);
      const previousMessages = currentThread
        ? currentThread.messages.filter(
            (m) => m.id !== tempAssistantMsg.id && m.id !== userMsg.id && !m.loading && !m.error
          )
        : [];
      const history = previousMessages
        .map((m) => ({
          role: m.role,
          content: m.role === 'user' ? m.content : (m.report?.ai_answer || m.content || ''),
        }))
        .slice(-6); // Cap to last 6 messages to match server-side window

      const report = await analyzeThreat(trimmed, 4, history);

      const finalAssistantMsg = {
        id: 'a-' + Date.now(),
        role: 'assistant',
        loading: false,
        report: report,
        model: report.ai_model || 'openai/gpt-oss-120b',
      };

      const finalizedThreads = updatedThreads.map((t) => {
        if (t.id === targetThreadId) {
          return {
            ...t,
            messages: t.messages.map((m) =>
              m.id === tempAssistantMsg.id ? finalAssistantMsg : m
            ),
          };
        }
        return t;
      });

      saveThreads(finalizedThreads);
    } catch (err) {
      const errorAssistantMsg = {
        id: 'a-' + Date.now(),
        role: 'assistant',
        loading: false,
        error: err.message || 'Failed to complete MITRE threat analysis.',
      };

      const finalizedThreads = updatedThreads.map((t) => {
        if (t.id === targetThreadId) {
          return {
            ...t,
            messages: t.messages.map((m) =>
              m.id === tempAssistantMsg.id ? errorAssistantMsg : m
            ),
          };
        }
        return t;
      });

      saveThreads(finalizedThreads);
    } finally {
      setLoading(false);
    }
  };

  const handleNewThread = () => {
    setActiveThreadId(null);
    setQuery('');
  };

  const handleSelectThread = (thread) => {
    setActiveThreadId(thread.id);
    setQuery('');
  };

  const handleDeleteThread = (threadId) => {
    const updated = threads.filter((t) => t.id !== threadId);
    saveThreads(updated);
    if (activeThreadId === threadId) {
      if (updated.length > 0) {
        setActiveThreadId(updated[0].id);
      } else {
        handleNewThread();
      }
    }
  };

  const handleClearThreads = () => {
    saveThreads([]);
    handleNewThread();
  };

  const handleSelectEntity = (entityId, entityType) => {
    setModalEntity({ id: entityId, type: entityType });
  };

  const isThreadEmpty = messages.length === 0;

  return (
    <div className="app-container">
      {/* Left Collapsible Threads Sidebar */}
      <Sidebar
        isOpen={sidebarOpen}
        onToggle={() => setSidebarOpen(!sidebarOpen)}
        threads={threads}
        activeThreadId={activeThreadId}
        onSelectThread={handleSelectThread}
        onNewThread={handleNewThread}
        onDeleteThread={handleDeleteThread}
        onClearThreads={handleClearThreads}
      />

      {/* Main Thread Content */}
      <main className={`main-content ${isThreadEmpty ? 'empty-view' : 'thread-view'}`}>
        {/* Top-Center Logo */}
        <TopLogo />

        {/* Conversation Thread Area */}
        <div className="thread-scroll-area">
          {isThreadEmpty ? (
            <div className="empty-state">
              <Shield size={36} className="empty-state-icon" strokeWidth={1.5} />
              <div className="empty-state-title">Ready for Threat Intelligence</div>
              <p className="empty-state-desc">
                Ask any question (e.g. &quot;How do attackers steal passwords from memory?&quot;), describe an observed attack, or query a technique ID. Each query and follow-up will continue right here in this thread.
              </p>
            </div>
          ) : (
            <div className="thread-messages-list">
              {messages.map((msg) => (
                <ThreadMessage
                  key={msg.id}
                  message={msg}
                  onSelectEntity={handleSelectEntity}
                />
              ))}
              <div ref={messagesEndRef} />
            </div>
          )}
        </div>

        {/* Single Pinned Bottom Prompt Bar */}
        <div className="thread-prompt-bar-container">
          <PromptBar
            query={query}
            setQuery={setQuery}
            onSubmit={handleRunAnalysis}
            loading={loading}
          />
        </div>
      </main>

      {/* Entity Inspector Modal */}
      {modalEntity && (
        <EntityModal
          entityId={modalEntity.id}
          entityType={modalEntity.type}
          onClose={() => setModalEntity(null)}
        />
      )}
    </div>
  );
}
