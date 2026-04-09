// ============================================================================
// EmptyState Component - Display when no data is available
// ============================================================================

import { ReactNode } from 'react';
import { FileQuestion } from 'lucide-react';
import { Button } from './Button';

interface EmptyStateProps {
  icon?: ReactNode;
  title: string;
  description?: string;
  action?: {
    label: string;
    onClick: () => void;
    icon?: ReactNode;
  };
}

export function EmptyState({ icon, title, description, action }: EmptyStateProps) {
  return (
    <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-12">
      <div className="text-center">
        <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-gray-100 text-gray-400 mb-4">
          {icon || <FileQuestion className="w-8 h-8" />}
        </div>
        <h3 className="text-lg font-semibold text-gray-900 mb-2">{title}</h3>
        {description && <p className="text-gray-500 mb-6 max-w-md mx-auto">{description}</p>}
        {action && (
          <Button onClick={action.onClick} icon={action.icon}>
            {action.label}
          </Button>
        )}
      </div>
    </div>
  );
}
