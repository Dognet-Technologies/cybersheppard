import { Table, SeverityBadge, StatusBadge } from 'cybersheppard-frontend';

const events = [
  { host: 'web-prod-01', event: 'Privilege escalation attempt', severity: 'critical', status: 'new', time: '12:04:21' },
  { host: 'db-prod-02', event: 'Failed sudo authentication', severity: 'high', status: 'acknowledged', time: '11:58:09' },
  { host: 'app-stg-04', event: 'New SUID binary detected', severity: 'medium', status: 'new', time: '11:47:55' },
  { host: 'mail-01', event: 'Outbound connection to known C2', severity: 'critical', status: 'new', time: '11:31:02' },
  { host: 'ci-runner-07', event: 'Package integrity mismatch', severity: 'low', status: 'resolved', time: '10:22:40' },
];

const columns = [
  { key: 'host', label: 'Host', sortable: true },
  { key: 'event', label: 'Event' },
  { key: 'severity', label: 'Severity', sortable: true, render: (r: any) => <SeverityBadge severity={r.severity} /> },
  { key: 'status', label: 'Status', render: (r: any) => <StatusBadge status={r.status} /> },
  { key: 'time', label: 'Time', className: 'text-gray-500' },
];

export const SecurityEvents = () => (
  <Table data={events} columns={columns} sortKey="severity" sortOrder="desc" onSort={() => {}} />
);

export const Loading = () => <Table data={[]} columns={columns} loading />;

export const Empty = () => (
  <Table data={[]} columns={columns} emptyMessage="No security events in the selected window" />
);
