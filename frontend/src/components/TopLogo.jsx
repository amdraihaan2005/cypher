import React, { memo } from 'react';

const TopLogo = memo(function TopLogo() {
  return (
    <header className="top-header">
      <div className="brand-logo">
        <img
          src="/cypherlogo.png"
          alt="CYPHER"
          className="brand-logo-img"
          onError={(e) => {
            // Fallback to jpg if png is not found
            if (!e.currentTarget.dataset.fallback) {
              e.currentTarget.dataset.fallback = 'true';
              e.currentTarget.src = '/cypherlogo.png.jpg';
            }
          }}
        />
      </div>
      <div className="brand-sub">AI CYBERSECURITY ASSISTANT</div>
    </header>
  );
});

export default TopLogo;
