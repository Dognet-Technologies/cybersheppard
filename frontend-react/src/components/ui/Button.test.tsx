import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Button } from './Button'

describe('Button', () => {
  it('renders its children as an accessible button', () => {
    render(<Button>Quarantine</Button>)
    expect(screen.getByRole('button', { name: 'Quarantine' })).toBeInTheDocument()
  })

  it('applies variant-specific classes', () => {
    render(<Button variant="outline">Dismiss</Button>)
    const btn = screen.getByRole('button', { name: 'Dismiss' })
    expect(btn.className).toContain('border')
    expect(btn.className).toContain('bg-transparent')
  })

  it('calls onClick when clicked', async () => {
    const onClick = vi.fn()
    render(<Button onClick={onClick}>Run scan</Button>)

    await userEvent.click(screen.getByRole('button', { name: 'Run scan' }))

    expect(onClick).toHaveBeenCalledTimes(1)
  })

  it('is disabled and shows a loading label while loading', async () => {
    const onClick = vi.fn()
    render(
      <Button loading onClick={onClick}>
        Apply hardening
      </Button>
    )
    const btn = screen.getByRole('button')

    expect(btn).toBeDisabled()
    expect(btn).toHaveTextContent('Loading...')

    await userEvent.click(btn)
    expect(onClick).not.toHaveBeenCalled()
  })

  it('honors the disabled prop', () => {
    render(<Button disabled>Delete</Button>)
    expect(screen.getByRole('button', { name: 'Delete' })).toBeDisabled()
  })
})
