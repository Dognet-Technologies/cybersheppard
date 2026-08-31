import { Select } from 'cybersheppard-frontend';

export const SeverityFilter = () => (
  <div className="max-w-xs">
    <Select defaultValue="high">
      <option value="all">All severities</option>
      <option value="critical">Critical</option>
      <option value="high">High</option>
      <option value="medium">Medium</option>
      <option value="low">Low</option>
    </Select>
  </div>
);

export const Disabled = () => (
  <div className="max-w-xs">
    <Select disabled defaultValue="nis2">
      <option value="nis2">NIS2</option>
      <option value="cis">CIS Benchmark</option>
    </Select>
  </div>
);
