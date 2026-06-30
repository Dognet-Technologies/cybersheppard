// ============================================================================
// Badge Component - Status and severity indicators
// ============================================================================

import clsx from 'clsx';

interface BadgeProps {
  children: React.ReactNode;
  variant?: 'success' | 'warning' | 'danger' | 'info' | 'default';
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

export function Badge({ children, variant = 'default', size = 'md', className }: BadgeProps) {
  const variants = {
    success: 'bg-green-100 text-green-800 border-green-200',
    warning: 'bg-yellow-100 text-yellow-800 border-yellow-200',
    danger: 'bg-red-100 text-red-800 border-red-200',
    info: 'bg-blue-100 text-blue-800 border-blue-200',
    default: 'bg-gray-100 text-gray-800 border-gray-200',
  };

  const sizes = {
    sm: 'px-2 py-0.5 text-xs',
    md: 'px-2.5 py-1 text-sm',
    lg: 'px-3 py-1.5 text-base',
  };

  return (
    <span
      className={clsx(
        'inline-flex items-center font-medium rounded-full border',
        variants[variant],
        sizes[size],
        className
      )}
    >
      {children}
    </span>
  );
}

interface SeverityBadgeProps {
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  className?: string;
}

export function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  const severityMap = {
    critical: { variant: 'danger' as const, label: 'Critical' },
    high: { variant: 'warning' as const, label: 'High' },
    medium: { variant: 'warning' as const, label: 'Medium' },
    low: { variant: 'info' as const, label: 'Low' },
    info: { variant: 'default' as const, label: 'Info' },
  };

  const config = severityMap[severity] || severityMap.info;

  return (
    <Badge variant={config.variant} className={className}>
      {config.label}
    </Badge>
  );
}

interface StatusBadgeProps {
  status: 'online' | 'offline' | 'active' | 'inactive' | 'new' | 'acknowledged' | 'resolved';
  className?: string;
}

export function StatusBadge({ status, className }: StatusBadgeProps) {
  const statusMap = {
    online: { variant: 'success' as const, label: 'Online' },
    offline: { variant: 'danger' as const, label: 'Offline' },
    active: { variant: 'success' as const, label: 'Active' },
    inactive: { variant: 'default' as const, label: 'Inactive' },
    new: { variant: 'info' as const, label: 'New' },
    acknowledged: { variant: 'warning' as const, label: 'Acknowledged' },
    resolved: { variant: 'success' as const, label: 'Resolved' },
  };

  const config = statusMap[status] || { variant: 'default' as const, label: status };

  return (
    <Badge variant={config.variant} className={className}>
      {config.label}
    </Badge>
  );
}
