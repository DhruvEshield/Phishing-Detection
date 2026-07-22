import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import type { RiskTier } from '../src/types';
import RiskBadge from '../src/components/RiskBadge';

describe('RiskBadge', () => {
  it.each<[RiskTier, string]>([
    ['CRITICAL', 'Critical'],
    ['HIGH', 'High'],
    ['MEDIUM', 'Medium'],
    ['LOW', 'Low'],
  ])('renders the %s tier with label "%s"', (tier, label) => {
    render(<RiskBadge tier={tier} />);
    expect(screen.getByText(label)).toBeInTheDocument();
  });

  it('falls back to the LOW rendering for an unknown tier', () => {
    // The component does `config[tier] ?? config.LOW` — an out-of-band value
    // must not crash and must render as Low.
    render(<RiskBadge tier={'BOGUS' as RiskTier} />);
    expect(screen.getByText('Low')).toBeInTheDocument();
  });

  it('applies the error color for CRITICAL/HIGH via the MUI Chip', () => {
    const { container } = render(<RiskBadge tier="CRITICAL" />);
    expect(container.querySelector('.MuiChip-colorError')).not.toBeNull();
  });
});
