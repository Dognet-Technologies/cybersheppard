import { Input } from 'cybersheppard-frontend';
import { Search, Globe } from 'lucide-react';

export const Default = () => (
  <div className="max-w-sm">
    <Input placeholder="Rule name" defaultValue="block-outbound-c2" />
  </div>
);

export const WithIcon = () => (
  <div className="max-w-sm space-y-3">
    <Input icon={<Search className="w-4 h-4" />} placeholder="Search hosts or events…" />
    <Input icon={<Globe className="w-4 h-4" />} placeholder="192.168.0.0/24" defaultValue="192.168.10.21" />
  </div>
);

export const States = () => (
  <div className="max-w-sm space-y-3">
    <Input placeholder="Enabled" />
    <Input placeholder="Disabled" disabled defaultValue="locked-by-policy" />
  </div>
);
