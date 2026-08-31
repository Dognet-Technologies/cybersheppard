import { Badge } from 'cybersheppard-frontend';

export const Variants = () => (
  <div className="flex flex-wrap items-center gap-2">
    <Badge variant="success">Resolved</Badge>
    <Badge variant="warning">Acknowledged</Badge>
    <Badge variant="danger">Critical</Badge>
    <Badge variant="info">New</Badge>
    <Badge variant="default">Inactive</Badge>
  </div>
);

export const Sizes = () => (
  <div className="flex flex-wrap items-center gap-2">
    <Badge variant="danger" size="sm">CVE-2024-3094</Badge>
    <Badge variant="danger" size="md">CVE-2024-3094</Badge>
    <Badge variant="danger" size="lg">CVE-2024-3094</Badge>
  </div>
);

export const InContext = () => (
  <div className="flex items-center gap-2 text-sm text-gray-700">
    <span>web-prod-01</span>
    <Badge variant="success">Online</Badge>
    <Badge variant="warning">3 findings</Badge>
  </div>
);
