import React from 'react';
import { Shield } from 'lucide-react';

export default function TopLogo() {
  return (
    <header className="top-header">
      <div className="brand-logo">
        <Shield className="brand-icon" strokeWidth={2.2} />
        <span className="brand-name">CYPHER AI</span>
      </div>
      <div className="brand-sub">MITRE ATT&amp;CK Intelligence Engine</div>
    </header>
  );
}
