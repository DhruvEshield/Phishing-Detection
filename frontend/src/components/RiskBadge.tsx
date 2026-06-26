import Chip from '@mui/material/Chip';
import type { RiskTier } from '../types';

const config: Record<RiskTier, { label: string; color: 'error' | 'warning' | 'info' | 'default' }> = {
  CRITICAL: { label: 'Critical', color: 'error' },
  HIGH:     { label: 'High',     color: 'error' },
  MEDIUM:   { label: 'Medium',   color: 'warning' },
  LOW:      { label: 'Low',      color: 'default' },
};

interface Props { tier: RiskTier; size?: 'small' | 'medium' }

export default function RiskBadge({ tier, size = 'small' }: Props) {
  const { label, color } = config[tier] ?? config.LOW;
  return <Chip label={label} color={color} size={size} variant="filled" />;
}
