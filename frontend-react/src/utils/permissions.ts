// ============================================================================
// CYBERSHEPPARD (MicroSIEM) - Permission Utilities
// ============================================================================

/**
 * User roles in the system
 * - admin: Full system access
 * - teamLeader: Team management and resource access
 * - user: Basic user access
 */
export type UserRole = 'admin' | 'teamLeader' | 'user';

/**
 * User interface matching backend AuthUser
 */
export interface User {
  id: number;
  username: string;
  email: string;
  role: UserRole;
  team_id?: number;
  managed_by?: number;
  is_active: boolean;
  created_at: string;
}

/**
 * Permission checker class
 */
export class Permissions {
  /**
   * Check if user is admin
   */
  static isAdmin(role: UserRole): boolean {
    return role === 'admin';
  }

  /**
   * Check if user is admin or team leader
   */
  static isAdminOrTeamLeader(role: UserRole): boolean {
    return role === 'admin' || role === 'teamLeader';
  }

  /**
   * Check if user can manage users
   * Admin: All users
   * TeamLeader: Team members only
   */
  static canManageUsers(role: UserRole): boolean {
    return role === 'admin' || role === 'teamLeader';
  }

  /**
   * Check if user can manage system settings
   * Admin only
   */
  static canManageSystemSettings(role: UserRole): boolean {
    return role === 'admin';
  }

  /**
   * Check if user can install/uninstall plugins
   * Admin only
   */
  static canManagePlugins(role: UserRole): boolean {
    return role === 'admin';
  }

  /**
   * Check if user can configure plugins
   * Admin and TeamLeader
   */
  static canConfigurePlugins(role: UserRole): boolean {
    return role === 'admin' || role === 'teamLeader';
  }

  /**
   * Check if user can view plugins
   * All authenticated users
   */
  static canViewPlugins(role: UserRole): boolean {
    return true;
  }

  /**
   * Check if user can create/edit/delete resources (targets, scans, etc.)
   * Admin and TeamLeader
   */
  static canManageResources(role: UserRole): boolean {
    return role === 'admin' || role === 'teamLeader';
  }

  /**
   * Check if user can execute scans
   * All authenticated users
   */
  static canExecuteScans(role: UserRole): boolean {
    return true;
  }

  /**
   * Check if user can view audit logs
   * Admin and TeamLeader
   */
  static canViewAuditLogs(role: UserRole): boolean {
    return role === 'admin' || role === 'teamLeader';
  }

  /**
   * Check if user can manage integrations
   * Admin and TeamLeader
   */
  static canManageIntegrations(role: UserRole): boolean {
    return role === 'admin' || role === 'teamLeader';
  }

  /**
   * Check if user can generate API keys
   * All users (own keys)
   */
  static canGenerateApiKeys(role: UserRole): boolean {
    return true;
  }

  /**
   * Check if user can view all API keys
   * Admin only
   */
  static canViewAllApiKeys(role: UserRole): boolean {
    return role === 'admin';
  }

  /**
   * Check if user can view team API keys
   * Admin and TeamLeader
   */
  static canViewTeamApiKeys(role: UserRole): boolean {
    return role === 'admin' || role === 'teamLeader';
  }

  /**
   * Check if user can edit specific resource
   * Admin: all resources
   * TeamLeader: team resources only
   * User: own resources only
   */
  static canEditResource(
    userRole: UserRole,
    userId: number,
    resourceOwnerId: number,
    resourceTeamId?: number,
    userTeamId?: number
  ): boolean {
    // Admin can edit everything
    if (userRole === 'admin') return true;

    // User owns the resource
    if (userId === resourceOwnerId) return true;

    // TeamLeader can edit team resources
    if (
      userRole === 'teamLeader' &&
      resourceTeamId &&
      userTeamId &&
      resourceTeamId === userTeamId
    ) {
      return true;
    }

    return false;
  }

  /**
   * Get role display name
   */
  static getRoleDisplayName(role: UserRole): string {
    const roleNames: Record<UserRole, string> = {
      admin: 'Administrator',
      teamLeader: 'Team Leader',
      user: 'User',
    };
    return roleNames[role];
  }

  /**
   * Get role badge color for UI
   */
  static getRoleBadgeColor(role: UserRole): string {
    const colors: Record<UserRole, string> = {
      admin: 'red',
      teamLeader: 'blue',
      user: 'gray',
    };
    return colors[role];
  }
}

/**
 * React hook for checking permissions
 */
export function usePermissions(role: UserRole) {
  return {
    isAdmin: Permissions.isAdmin(role),
    isAdminOrTeamLeader: Permissions.isAdminOrTeamLeader(role),
    canManageUsers: Permissions.canManageUsers(role),
    canManageSystemSettings: Permissions.canManageSystemSettings(role),
    canManagePlugins: Permissions.canManagePlugins(role),
    canConfigurePlugins: Permissions.canConfigurePlugins(role),
    canViewPlugins: Permissions.canViewPlugins(role),
    canManageResources: Permissions.canManageResources(role),
    canExecuteScans: Permissions.canExecuteScans(role),
    canViewAuditLogs: Permissions.canViewAuditLogs(role),
    canManageIntegrations: Permissions.canManageIntegrations(role),
    canGenerateApiKeys: Permissions.canGenerateApiKeys(role),
    canViewAllApiKeys: Permissions.canViewAllApiKeys(role),
    canViewTeamApiKeys: Permissions.canViewTeamApiKeys(role),
  };
}

/**
 * Higher-order component for protected routes
 */
export function withPermission<P extends object>(
  Component: React.ComponentType<P>,
  requiredPermission: (role: UserRole) => boolean
) {
  return function ProtectedComponent(props: P & { userRole: UserRole }) {
    const { userRole, ...rest } = props;

    if (!requiredPermission(userRole)) {
      return (
        <div className="flex items-center justify-center h-screen">
          <div className="text-center">
            <h1 className="text-2xl font-bold text-red-600 mb-2">
              Access Denied
            </h1>
            <p className="text-gray-600">
              You don't have permission to access this page.
            </p>
          </div>
        </div>
      );
    }

    return <Component {...(rest as P)} />;
  };
}
