import { describe, it, expect } from 'vitest'
import { Permissions, type UserRole } from './permissions'

const ROLES: UserRole[] = ['admin', 'teamLeader', 'user']

describe('Permissions — role predicates', () => {
  it('recognizes only admin as admin', () => {
    expect(Permissions.isAdmin('admin')).toBe(true)
    expect(Permissions.isAdmin('teamLeader')).toBe(false)
    expect(Permissions.isAdmin('user')).toBe(false)
  })

  it('treats admin and teamLeader as elevated', () => {
    expect(Permissions.isAdminOrTeamLeader('admin')).toBe(true)
    expect(Permissions.isAdminOrTeamLeader('teamLeader')).toBe(true)
    expect(Permissions.isAdminOrTeamLeader('user')).toBe(false)
  })

  it('restricts system settings and plugin management to admin only', () => {
    expect(Permissions.canManageSystemSettings('admin')).toBe(true)
    expect(Permissions.canManageSystemSettings('teamLeader')).toBe(false)
    expect(Permissions.canManagePlugins('teamLeader')).toBe(false)
    expect(Permissions.canManagePlugins('admin')).toBe(true)
    expect(Permissions.canViewAllApiKeys('user')).toBe(false)
  })

  it('lets admin and teamLeader manage users, resources, integrations and audit logs', () => {
    for (const role of ['admin', 'teamLeader'] as UserRole[]) {
      expect(Permissions.canManageUsers(role)).toBe(true)
      expect(Permissions.canManageResources(role)).toBe(true)
      expect(Permissions.canManageIntegrations(role)).toBe(true)
      expect(Permissions.canViewAuditLogs(role)).toBe(true)
      expect(Permissions.canConfigurePlugins(role)).toBe(true)
    }
    expect(Permissions.canManageUsers('user')).toBe(false)
    expect(Permissions.canViewAuditLogs('user')).toBe(false)
  })

  it('grants view/scan/api-key basics to every authenticated role', () => {
    for (const role of ROLES) {
      expect(Permissions.canViewPlugins(role)).toBe(true)
      expect(Permissions.canExecuteScans(role)).toBe(true)
      expect(Permissions.canGenerateApiKeys(role)).toBe(true)
    }
  })
})

describe('Permissions.canEditResource', () => {
  it('lets admin edit any resource', () => {
    expect(Permissions.canEditResource('admin', 1, 999)).toBe(true)
  })

  it('lets a user edit only resources they own', () => {
    expect(Permissions.canEditResource('user', 7, 7)).toBe(true)
    expect(Permissions.canEditResource('user', 7, 8)).toBe(false)
  })

  it('lets a teamLeader edit resources in their own team but not other teams', () => {
    // same team → allowed
    expect(Permissions.canEditResource('teamLeader', 2, 50, 10, 10)).toBe(true)
    // different team → denied
    expect(Permissions.canEditResource('teamLeader', 2, 50, 20, 10)).toBe(false)
    // missing team info → denied
    expect(Permissions.canEditResource('teamLeader', 2, 50)).toBe(false)
  })
})

describe('Permissions — display helpers', () => {
  it('maps each role to a human label', () => {
    expect(Permissions.getRoleDisplayName('admin')).toBe('Administrator')
    expect(Permissions.getRoleDisplayName('teamLeader')).toBe('Team Leader')
    expect(Permissions.getRoleDisplayName('user')).toBe('User')
  })

  it('maps each role to a badge color', () => {
    expect(Permissions.getRoleBadgeColor('admin')).toBe('red')
    expect(Permissions.getRoleBadgeColor('teamLeader')).toBe('blue')
    expect(Permissions.getRoleBadgeColor('user')).toBe('gray')
  })
})
