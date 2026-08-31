import { Button } from 'cybersheppard-frontend';
import { Shield, RefreshCw, Trash2, Download } from 'lucide-react';

export const Variants = () => (
  <div className="flex flex-wrap items-center gap-3">
    <Button variant="primary">Run Scan</Button>
    <Button variant="secondary">Export</Button>
    <Button variant="danger">Quarantine Host</Button>
    <Button variant="ghost">Dismiss</Button>
    <Button variant="outline">View Details</Button>
  </div>
);

export const Sizes = () => (
  <div className="flex flex-wrap items-center gap-3">
    <Button size="sm">Small</Button>
    <Button size="md">Medium</Button>
    <Button size="lg">Large</Button>
  </div>
);

export const WithIcons = () => (
  <div className="flex flex-wrap items-center gap-3">
    <Button variant="primary" icon={<Shield className="w-4 h-4" />}>Harden</Button>
    <Button variant="secondary" icon={<RefreshCw className="w-4 h-4" />}>Re-scan</Button>
    <Button variant="outline" icon={<Download className="w-4 h-4" />} iconPosition="right">Report</Button>
    <Button variant="danger" icon={<Trash2 className="w-4 h-4" />}>Delete Rule</Button>
  </div>
);

export const States = () => (
  <div className="flex flex-wrap items-center gap-3">
    <Button variant="primary" loading>Scanning…</Button>
    <Button variant="primary" disabled>Disabled</Button>
    <Button variant="primary" fullWidth>Apply Hardening Template</Button>
  </div>
);
