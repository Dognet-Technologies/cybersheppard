// ============================================================================
// Stats Component - Metric cards for dashboard statistics
// ============================================================================

import { ReactNode } from 'react';
import clsx from 'clsx';
import { TrendingUp, TrendingDown } from 'lucide-react';
import { InfoTip } from './Tooltip';

interface StatCardProps {
  title: string;
  value: string | number;
  icon?: ReactNode;
  subtitle?: string;
  trend?: {
    value: number;
    label: string;
  };
  variant?: 'default' | 'success' | 'warning' | 'danger' | 'info';
  className?: string;
  /** Spiegazione della metrica mostrata dall’icona “?” accanto al titolo. */
  info?: ReactNode;
}

export function StatCard({
  title,
  value,
  icon,
  subtitle,
  trend,
  variant = 'default',
  className,
  info,
}: StatCardProps) {
  const variants = {
    default: 'bg-white border-gray-200',
    success: 'bg-green-50 border-green-200',
    warning: 'bg-yellow-50 border-yellow-200',
    danger: 'bg-red-50 border-red-200',
    info: 'bg-blue-50 border-blue-200',
  };

  const iconColors = {
    default: 'bg-gray-100 text-gray-600',
    success: 'bg-green-100 text-green-600',
    warning: 'bg-yellow-100 text-yellow-600',
    danger: 'bg-red-100 text-red-600',
    info: 'bg-blue-100 text-blue-600',
  };

  return (
    <div
      className={clsx(
        'rounded-lg border shadow-sm p-6',
        variants[variant],
        className
      )}
    >
      <div className="flex items-center justify-between">
        <div className="flex-1">
          <p className="text-sm font-medium text-gray-600 mb-1 flex items-center gap-1.5">
            {title}
            {info && <InfoTip content={info} />}
          </p>
          <p className="text-3xl font-bold text-gray-900">{value}</p>

          {subtitle && (
            <p className="mt-1 text-sm text-gray-500">{subtitle}</p>
          )}

          {trend && (
            <div className="mt-2 flex items-center text-sm">
              {trend.value >= 0 ? (
                <TrendingUp className="w-4 h-4 text-green-600 mr-1" />
              ) : (
                <TrendingDown className="w-4 h-4 text-red-600 mr-1" />
              )}
              <span
                className={clsx(
                  'font-medium',
                  trend.value >= 0 ? 'text-green-600' : 'text-red-600'
                )}
              >
                {Math.abs(trend.value)}%
              </span>
              <span className="text-gray-500 ml-1">{trend.label}</span>
            </div>
          )}
        </div>

        {icon && (
          <div
            className={clsx(
              'w-12 h-12 rounded-lg flex items-center justify-center',
              iconColors[variant]
            )}
          >
            {icon}
          </div>
        )}
      </div>
    </div>
  );
}

interface StatsGridProps {
  children: ReactNode;
  columns?: 2 | 3 | 4;
  className?: string;
}

export function StatsGrid({ children, columns = 4, className }: StatsGridProps) {
  const gridCols = {
    2: 'grid-cols-1 md:grid-cols-2',
    3: 'grid-cols-1 md:grid-cols-2 lg:grid-cols-3',
    4: 'grid-cols-1 md:grid-cols-2 lg:grid-cols-4',
  };

  return (
    <div className={clsx('grid gap-6', gridCols[columns], className)}>
      {children}
    </div>
  );
}
