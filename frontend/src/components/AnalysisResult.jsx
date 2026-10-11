import React, { memo, useMemo } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { Target, ShieldCheck, Users, Wrench, Sparkles } from 'lucide-react';

const AnalysisResult = memo(function AnalysisResult({ report, onSelectEntity }) {
  if (!report) return null;

  const techniques = report.identified_techniques || [];
  const mitigations = report.prioritized_mitigations || [];
  const groups = report.attributed_groups || [];
  const software = report.identified_software || [];
  const aiAnswer = report.ai_answer;

  const renderedMarkdown = useMemo(() => {
    if (!aiAnswer) return null;
    return (
      <ReactMarkdown remarkPlugins={[remarkGfm]}>
        {aiAnswer}
      </ReactMarkdown>
    );
  }, [aiAnswer]);

  const hasEntities = techniques.length > 0 || mitigations.length > 0 || groups.length > 0 || software.length > 0;

  if (!aiAnswer && !hasEntities) {
    return (
      <div className="results-container">
        <section className="result-section ai-answer-card">
          <div className="section-header">
            <div className="section-title" style={{ color: '#38bdf8' }}>
              <Sparkles size={16} />
              <span>Cypher AI Intelligence Profile</span>
            </div>
          </div>
          <div className="ai-answer-body markdown-content" style={{ color: 'var(--text-secondary)' }}>
            <p>I am ready to assist with MITRE ATT&amp;CK intelligence. Describe an observed threat activity, attack vector, or technique ID to generate an intelligence profile.</p>
          </div>
        </section>
      </div>
    );
  }

  return (
    <div className="results-container">
      {/* 1. Direct AI Answer Card */}
      <section className="result-section ai-answer-card">
        <div className="section-header">
          <div className="section-title" style={{ color: '#38bdf8' }}>
            <Sparkles size={16} />
            <span>Cypher AI Intelligence</span>
          </div>
        </div>
        <div className="ai-answer-body markdown-content">
          {renderedMarkdown || (
            <p style={{ color: 'var(--text-secondary)' }}>
              Analysis complete. Retrieved {techniques.length} technique(s), {mitigations.length} mitigation(s), and {groups.length} threat actor(s) from the MITRE ATT&amp;CK knowledge graph.
            </p>
          )}
        </div>
      </section>

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
                    role="button"
                    tabIndex={0}
                    onClick={() => onSelectEntity?.(id, 'technique')}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        onSelectEntity?.(id, 'technique');
                      }
                    }}
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
                    role="button"
                    tabIndex={0}
                    onClick={() => onSelectEntity?.(id, 'mitigation')}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        onSelectEntity?.(id, 'mitigation');
                      }
                    }}
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
                    role="button"
                    tabIndex={0}
                    onClick={() => onSelectEntity?.(id, 'group')}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        onSelectEntity?.(id, 'group');
                      }
                    }}
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
                    role="button"
                    tabIndex={0}
                    onClick={() => onSelectEntity?.(id, 'software')}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        onSelectEntity?.(id, 'software');
                      }
                    }}
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
});

export default AnalysisResult;

