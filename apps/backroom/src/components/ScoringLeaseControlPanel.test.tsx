// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  scoringLeaseConfirmation,
  type ScoringLeaseSettingsControl,
} from '../lib/admin.schemas'
import { ScoringLeaseControlPanel } from './ScoringLeaseControlPanel'

const getScoringLeaseSettings = vi.fn()
const updateScoringLeaseSettings = vi.fn()

vi.mock('@tanstack/react-start', () => ({ useServerFn: (value: unknown) => value }))
vi.mock('../server/admin.functions', () => ({
  getScoringLeaseSettings: () => getScoringLeaseSettings(),
  updateScoringLeaseSettings: (input: unknown) => updateScoringLeaseSettings(input),
}))

const initial: ScoringLeaseSettingsControl = {
  current: [],
  history: [],
  default: { scoring_ticket_ttl_minutes: 180 },
  effective: {
    revision: 0,
    scope: '*',
    settings: { scoring_ticket_ttl_minutes: 180 },
    checksum: '',
    source: 'default',
    min_scoring_ticket_ttl_minutes: 60,
    max_scoring_ticket_ttl_minutes: 240,
    max_age_seconds: 5,
  },
}

describe('ScoringLeaseControlPanel', () => {
  afterEach(cleanup)

  beforeEach(() => {
    getScoringLeaseSettings.mockReset().mockResolvedValue(initial)
    updateScoringLeaseSettings.mockReset().mockResolvedValue({
      ...initial,
      effective: {
        ...initial.effective,
        revision: 1,
        source: 'revision',
        settings: { scoring_ticket_ttl_minutes: 150 },
      },
    })
  })

  it('shows the shipped default and requires reason plus exact confirmation', async () => {
    render(<ScoringLeaseControlPanel initialState={initial} readOnly={false} />)

    expect(screen.getByText('180 minutes')).toBeTruthy()
    expect(screen.getAllByText('Shipped default').length).toBeGreaterThan(0)
    fireEvent.change(screen.getByLabelText(/Scoring TTL in minutes/), {
      target: { value: '150' },
    })
    const action = screen.getByRole('button', { name: 'Apply scoring TTL' })
    expect((action as HTMLButtonElement).disabled).toBe(true)

    fireEvent.change(screen.getByLabelText('Lease change reason'), {
      target: { value: 'v11 completions fit well inside 150 minutes' },
    })
    const expected = scoringLeaseConfirmation(150)
    fireEvent.change(screen.getByLabelText(new RegExp(expected)), {
      target: { value: expected },
    })
    expect((action as HTMLButtonElement).disabled).toBe(false)
    fireEvent.click(action)

    await waitFor(() => expect(updateScoringLeaseSettings).toHaveBeenCalledTimes(1))
    expect(updateScoringLeaseSettings).toHaveBeenCalledWith({
      data: {
        scope: '*',
        expectedRevision: 0,
        settings: { scoring_ticket_ttl_minutes: 150 },
        reason: 'v11 completions fit well inside 150 minutes',
        confirmation: expected,
      },
    })
    await waitFor(() => expect(screen.getByText('150 minutes')).toBeTruthy())
  })

  it('refuses an out-of-range TTL before any write', () => {
    render(<ScoringLeaseControlPanel initialState={initial} readOnly={false} />)

    fireEvent.change(screen.getByLabelText(/Scoring TTL in minutes/), {
      target: { value: '430' },
    })
    expect(screen.getByText('Enter a whole number from 60 through 240.')).toBeTruthy()
    expect(
      (screen.getByRole('button', { name: 'Apply scoring TTL' }) as HTMLButtonElement).disabled,
    ).toBe(true)
  })

  it('keeps Apply disabled for a whitespace-only reason', () => {
    render(<ScoringLeaseControlPanel initialState={initial} readOnly={false} />)

    fireEvent.change(screen.getByLabelText(/Scoring TTL in minutes/), {
      target: { value: '150' },
    })
    fireEvent.change(screen.getByLabelText('Lease change reason'), {
      target: { value: '            ' },
    })
    const expected = scoringLeaseConfirmation(150)
    fireEvent.change(screen.getByLabelText(new RegExp(expected)), {
      target: { value: expected },
    })
    expect(
      (screen.getByRole('button', { name: 'Apply scoring TTL' }) as HTMLButtonElement).disabled,
    ).toBe(true)
  })

  it('shows the refusal and its specific recovery verbatim and keeps the form', async () => {
    const refusal =
      'confirmation must be exactly APPLY SCORING TICKET TTL 150 MINUTES. Nothing was applied: the confirmation must name the TTL this revision applies, typed out rather than derived from the number above it.'
    updateScoringLeaseSettings.mockReset().mockRejectedValue(new Error(refusal))
    render(<ScoringLeaseControlPanel initialState={initial} readOnly={false} />)

    fireEvent.change(screen.getByLabelText(/Scoring TTL in minutes/), {
      target: { value: '150' },
    })
    fireEvent.change(screen.getByLabelText('Lease change reason'), {
      target: { value: 'v11 completions fit well inside 150 minutes' },
    })
    const expected = scoringLeaseConfirmation(150)
    fireEvent.change(screen.getByLabelText(new RegExp(expected)), {
      target: { value: expected },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Apply scoring TTL' }))

    await waitFor(() => expect(screen.getByText(refusal)).toBeTruthy())
    // The operator's input survives so they can fix only what was refused.
    expect((screen.getByLabelText('Lease change reason') as HTMLInputElement).value).toBe(
      'v11 completions fit well inside 150 minutes',
    )
    expect(screen.getByText('180 minutes')).toBeTruthy()
  })

  it('keeps write controls disabled for read-only operators', () => {
    render(<ScoringLeaseControlPanel initialState={initial} readOnly />)

    expect((screen.getByLabelText(/Scoring TTL in minutes/) as HTMLInputElement).disabled).toBe(
      true,
    )
    expect(
      (screen.getByRole('button', { name: 'Apply scoring TTL' }) as HTMLButtonElement).disabled,
    ).toBe(true)
  })
})
