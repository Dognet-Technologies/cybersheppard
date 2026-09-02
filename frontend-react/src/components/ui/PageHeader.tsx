// ============================================================================
// PageHeader Component - Consistent page headers with actions
// ============================================================================

import { ReactNode } from 'react';
import clsx from 'clsx';
import { InfoTip } from './Tooltip';

interface PageHeaderProps {
  title: string;
  subtitle?: string;
  icon?: ReactNode;
  actions?: ReactNode;
  breadcrumbs?: { label: string; href?: string }[];
  className?: string;
  /** Spiegazione approfondita mostrata dall’icona “?” accanto al titolo. */
  info?: ReactNode;
}

export function PageHeader({
  title,
  subtitle,
  icon,
  actions,
  breadcrumbs,
  className,
  info,
}: PageHeaderProps) {
  return (
    <div className={clsx('mb-8', className)}>
      {breadcrumbs && breadcrumbs.length > 0 && (
        <nav className="mb-4">
          <ol className="flex items-center space-x-2 text-sm text-gray-500">
            {breadcrumbs.map((crumb, index) => (
              <li key={index} className="flex items-center">
                {index > 0 && <span className="mx-2">/</span>}
                {crumb.href ? (
                  <a href={crumb.href} className="hover:text-gray-700">
                    {crumb.label}
                  </a>
                ) : (
                  <span className="text-gray-900 font-medium">{crumb.label}</span>
                )}
              </li>
            ))}
          </ol>
        </nav>
      )}

      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-4">
          {icon && (
            <div className="flex-shrink-0 w-12 h-12 bg-blue-100 rounded-lg flex items-center justify-center text-blue-600">
              {icon}
            </div>
          )}
          <div>
            <h1 className="text-3xl font-bold text-gray-900 flex items-center gap-2">
              {title}
              {info && <InfoTip content={info} side="bottom" className="mt-1" />}
            </h1>
            {subtitle && <p className="mt-1 text-gray-500">{subtitle}</p>}
          </div>
        </div>

        {actions && <div className="flex items-center space-x-3">{actions}</div>}
      </div>
    </div>
  );
}
