import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { Badge, SeverityBadge, StatusBadge } from './Badge'

describe('Badge', () => {
  it('renders its children', () => {
    render(<Badge>Online</Badge>)
    expect(screen.getByText('Online')).toBeInTheDocument()
  })

  it('applies the color classes for the given variant', () => {
    render(<Badge variant="danger">Critical</Badge>)
    expect(screen.getByText('Critical').className).toContain('bg-red-100')
  })
})

describe('SeverityBadge', () => {
  it('maps each severity to its label', () => {
    const cases: Array<[Parameters<typeof SeverityBadge>[0]['severity'], string]> = [
      ['critical', 'Critical'],
      ['high', 'High'],
      ['medium', 'Medium'],
      ['low', 'Low'],
      ['info', 'Info'],
    ]
    for (const [severity, label] of cases) {
      const { unmount } = render(<SeverityBadge severity={severity} />)
      expect(screen.getByText(label)).toBeInTheDocument()
      unmount()
    }
  })

  it('renders critical severity with the danger color', () => {
    render(<SeverityBadge severity="critical" />)
    expect(screen.getByText('Critical').className).toContain('bg-red-100')
  })
})

describe('StatusBadge', () => {
  it('maps known statuses to their labels', () => {
    const { unmount } = render(<StatusBadge status="online" />)
    expect(screen.getByText('Online')).toBeInTheDocument()
    unmount()

    render(<StatusBadge status="acknowledged" />)
    expect(screen.getByText('Acknowledged')).toBeInTheDocument()
  })

  it('renders online status with the success color', () => {
    render(<StatusBadge status="online" />)
    expect(screen.getByText('Online').className).toContain('bg-green-100')
  })
})
