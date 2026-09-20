import React from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { Target, ShieldCheck, Users, Wrench, ChevronRight, Sparkles } from 'lucide-react';

export default function AnalysisResult({ report, onSelectEntity }) {
  if (!report) return null;

  const techniques = report.identified_techniques || [];
  const mitigations = report.prioritized_mitigations || [];
  const groups = report.attributed_groups || [];
  const software = report.identified_software || [];
  const aiAnswer = report.ai_answer;
  const aiModel = report.ai_model || 'openai/gpt-oss-120b';

  return (
    <div className="results-container">
      {/* 1. Direct AI Answer Card */}
      {aiAnswer && (
        <section className="result-section ai-answer-card">
          <div className="section-header">
            <div className="section-title" style={{ color: '#38bdf8' }}>
              <Sparkles size={16} />
              <span>Cypher AI Intelligence Profile</span>
            </div>
            <span className="badge-count" style={{ background: 'rgba(56, 189, 248, 0.15)', color: '#38bdf8' }}>
              {aiModel}
            </span>
          </div>
          <div className="ai-answer-body markdown-content">
            <ReactMarkdown remarkPlugins={[remarkGfm]}>
              {aiAnswer}
            </ReactMarkdown>
          </div>
        </section>
      )}

      {/* 2. Unified Entity Meta Pills (Techniques, Mitigations, Threat Actors, Tools/Malware) */}
      {(techniques.length > 0 || mitigations.length > 0 || groups.length > 0 || software.length > 0) && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '14px' }}>
          {techniques.length > 0 && (
            <div className="meta-pill-group">
              <span className="meta-label">
                <Target size={12} style={{ color: '#38bdf8' }} /> Techniques:
              </span>
              {techniques.map((tech, idx) => {
                const id = tech.attack_id || tech.id;
                const name = tech.name;
                return (
                  <span
                    key={id || idx}
                    className="sw-pill"
                    style={{ cursor: 'pointer' }}
                    onClick={() => onSelectEntity(id, 'technique')}
                    title="Click to inspect technique"
                  >
                    <strong style={{ color: '#38bdf8', marginRight: '4px' }}>{id}</strong>
                    {name}
                  </span>
                );
              })}
            </div>
          )}

          {mitigations.length > 0 && (
            <div className="meta-pill-group">
              <span className="meta-label">
                <ShieldCheck size={12} style={{ color: '#34d399' }} /> Mitigations:
              </span>
              {mitigations.map((mit, idx) => {
                const mitObj = mit.mitigation || mit;
                const id = mitObj.attack_id || mitObj.id;
                const name = mitObj.name;
                return (
                  <span
                    key={id || idx}
                    className="sw-pill"
                    style={{ cursor: 'pointer' }}
                    onClick={() => onSelectEntity(id, 'mitigation')}
                    title="Click to inspect mitigation"
                  >
                    <strong style={{ color: '#34d399', marginRight: '4px' }}>{id}</strong>
                    {name}
                  </span>
                );
              })}
            </div>
          )}

          {groups.length > 0 && (
            <div className="meta-pill-group">
              <span className="meta-label">
                <Users size={12} style={{ color: '#f59e0b' }} /> Threat Actors:
              </span>
              {groups.slice(0, 4).map((grp, idx) => {
                const groupObj = grp.group || grp;
                const id = groupObj.attack_id || groupObj.id;
                const name = groupObj.name;
                return (
                  <span
                    key={id || idx}
                    className="sw-pill"
                    style={{ cursor: 'pointer' }}
                    onClick={() => onSelectEntity(id, 'group')}
                    title="Click to inspect group"
                  >
                    <strong style={{ color: '#f59e0b', marginRight: '4px' }}>{id}</strong>
                    {name}
                  </span>
                );
              })}
            </div>
          )}

          {software.length > 0 && (
            <div className="meta-pill-group">
              <span className="meta-label">
                <Wrench size={12} style={{ color: '#a78bfa' }} /> Tools/Malware:
              </span>
              {software.slice(0, 5).map((sw, idx) => {
                const swObj = sw.software || sw;
                const id = swObj.attack_id || swObj.id;
                const name = swObj.name;
                return (
                  <span
                    key={id || idx}
                    className="sw-pill"
                    style={{ cursor: 'pointer' }}
                    onClick={() => onSelectEntity(id, 'software')}
                    title="Click to inspect software"
                  >
                    <strong style={{ color: '#a78bfa', marginRight: '4px' }}>{id}</strong>
                    {name}
                  </span>
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

