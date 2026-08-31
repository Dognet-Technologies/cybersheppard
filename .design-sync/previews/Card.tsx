import { Card, CardHeader, CardSection, Badge, Button } from 'cybersheppard-frontend';

export const Basic = () => (
  <Card className="max-w-md">
    <p className="text-sm text-gray-700">
      Auditd is collecting events on 12 monitored hosts. Last sync 2 minutes ago.
    </p>
  </Card>
);

export const WithHeaderAndSections = () => (
  <Card className="max-w-md">
    <CardHeader
      title="web-prod-01"
      subtitle="Ubuntu 22.04 · 192.168.10.21"
      action={<Badge variant="success">Online</Badge>}
    />
    <CardSection border>
      <div className="flex items-center justify-between text-sm">
        <span className="text-gray-500">Compliance score</span>
        <span className="font-semibold text-gray-900">86%</span>
      </div>
    </CardSection>
    <CardSection border>
      <div className="flex items-center justify-between text-sm">
        <span className="text-gray-500">Open findings</span>
        <Badge variant="warning">4 high</Badge>
      </div>
    </CardSection>
  </Card>
);

export const Padding = () => (
  <div className="flex flex-wrap gap-4">
    <Card padding="sm" className="text-xs text-gray-600">padding sm</Card>
    <Card padding="md" className="text-xs text-gray-600">padding md</Card>
    <Card padding="lg" className="text-xs text-gray-600">padding lg</Card>
  </div>
);

export const Hoverable = () => (
  <Card hover className="max-w-xs">
    <CardHeader title="Hardening Template" subtitle="CIS Ubuntu 22.04 — Level 1" />
    <Button variant="outline" size="sm">Apply</Button>
  </Card>
);
