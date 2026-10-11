import React, { useEffect, useState, memo } from 'react';
import { X, ExternalLink } from 'lucide-react';
import { getEntityDetail } from '../api';

const EntityModal = memo(function EntityModal({ entityId, entityType, onClose }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!entityId) return;
    const controller = new AbortController();
    setLoading(true);
    setError(null);

    getEntityDetail(entityId, entityType, { signal: controller.signal })
      .then((res) => {
        setData(res);
        setLoading(false);
      })
      .catch((err) => {
        if (controller.signal.aborted || err?.status === 499) {
          return;
        }
        setError(err.message || 'Failed to load entity details');
        setLoading(false);
      });

    return () => {
      controller.abort();
    };
  }, [entityId, entityType]);

  // Handle Escape key listener and body scroll lock
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape') {
        onClose?.();
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    const originalOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';

    return () => {
      window.removeEventListener('keydown', handleKeyDown);
      document.body.style.overflow = originalOverflow;
    };
  }, [onClose]);

  const getMitreUrl = () => {
    if (!entityId) return null;
    const cleanId = entityId.toUpperCase();
    // Check TA (tactics) before T (techniques) — TA0001 starts with 'T' too
    if (cleanId.startsWith('TA')) {
      return `https://attack.mitre.org/tactics/${cleanId}/`;
    }
    if (cleanId.startsWith('T')) {
      // Sub-technique e.g. T1059.001 -> /techniques/T1059/001/
      const parts = cleanId.split('.');
      if (parts.length === 2) {
        return `https://attack.mitre.org/techniques/${parts[0]}/${parts[1]}/`;
      }
      return `https://attack.mitre.org/techniques/${cleanId}/`;
    }
    if (cleanId.startsWith('G')) {
      return `https://attack.mitre.org/groups/${cleanId}/`;
    }
    if (cleanId.startsWith('S')) {
      return `https://attack.mitre.org/software/${cleanId}/`;
    }
    if (cleanId.startsWith('M')) {
      return `https://attack.mitre.org/mitigations/${cleanId}/`;
    }
    return null;
  };

  const entity = data?.technique || data?.mitigation || data?.group || data?.software || data?.tactic || data;

  return (
    <div
      className="modal-overlay"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-labelledby="modal-entity-title"
    >
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div>
            <div className="modal-type-badge">{entityType || 'MITRE ATT&CK'}</div>
            <h3 id="modal-entity-title" className="modal-title">
              {entity?.name || entityId}
            </h3>
          </div>
          <button className="modal-close-btn" onClick={onClose} aria-label="Close modal" type="button">
            <X size={18} />
          </button>
        </div>

        <div className="modal-body">
          {loading && (
            <div style={{ textAlign: 'center', padding: '30px', color: 'var(--text-muted)' }}>
              Loading MITRE entity details...
            </div>
          )}

          {error && (
            <div style={{ color: 'var(--danger)', padding: '12px' }}>
              Error loading details: {error}
            </div>
          )}

          {entity && !loading && (
            <>
              <div className="modal-field-group">
                <span className="modal-field-label">Entity ID</span>
                <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent)', fontWeight: 600 }}>
                  {entity.attack_id || entity.id || entityId}
                </span>
              </div>

              {entity.type && (
                <div className="modal-field-group">
                  <span className="modal-field-label">Category / Type</span>
                  <span style={{ textTransform: 'capitalize', color: 'var(--text-primary)' }}>
                    {entity.type}
                  </span>
                </div>
              )}

              {entity.description && (
                <div className="modal-field-group">
                  <span className="modal-field-label">Description</span>
                  <p style={{ color: 'var(--text-secondary)', fontSize: '13px', lineHeight: 1.6, marginTop: '2px', whiteSpace: 'pre-wrap' }}>
                    {entity.description}
                  </p>
                </div>
              )}

              {entity.tactics && entity.tactics.length > 0 && (
                <div className="modal-field-group">
                  <span className="modal-field-label">Tactics</span>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', marginTop: '4px' }}>
                    {entity.tactics.map((t, idx) => (
                      <span key={idx} className="tactic-tag">{t}</span>
                    ))}
                  </div>
                </div>
              )}

              {entity.platforms && entity.platforms.length > 0 && (
                <div className="modal-field-group">
                  <span className="modal-field-label">Platforms</span>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', marginTop: '4px' }}>
                    {entity.platforms.map((p, idx) => (
                      <span key={idx} className="sw-pill">{p}</span>
                    ))}
                  </div>
                </div>
              )}

              {entity.aliases && entity.aliases.length > 0 && (
                <div className="modal-field-group">
                  <span className="modal-field-label">Associated Aliases</span>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', marginTop: '4px' }}>
                    {entity.aliases.map((a, idx) => (
                      <span key={idx} className="sw-pill">{a}</span>
                    ))}
                  </div>
                </div>
              )}

              {getMitreUrl() && (
                <div style={{ marginTop: '20px' }}>
                  <a
                    href={getMitreUrl()}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="modal-link-btn"
                  >
                    <span>View on Official MITRE ATT&amp;CK</span>
                    <ExternalLink size={13} />
                  </a>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
});

export default EntityModal;

