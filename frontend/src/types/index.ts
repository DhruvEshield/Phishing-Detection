/**Shared TypeScript types for the PhishDetect frontend.*/

export interface SignalBreakdown {
  signal_name: string;
  raw_score: number;
  weight: number;
  weighted_contribution: number;
  flags: string[];
  metadata: Record<string, unknown>;
}

export interface ScoreExplanation {
  signals: SignalBreakdown[];
  model_version: string;
}

export type RiskTier = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type Verdict = 'PHISHING' | 'SUSPICIOUS' | 'LEGITIMATE' | 'UNKNOWN';
export type RoutingDecision = 'quarantine' | 'review' | 'deliver';
export type VerdictAction = 'approve' | 'quarantine';
export type QueueStatus = 'pending' | 'reviewed';

export interface EmailSummary {
  email_id: string;
  sender: string;
  subject: string;
  received_at: string;
  risk_score: number;
  risk_tier: RiskTier;
  verdict: Verdict;
  status: QueueStatus;
  tenant_id: string | null;
}

export interface EmailDetail {
  email_id: string;
  sender: string;
  subject: string;
  received_at: string;
  body_text: string;
  headers: Record<string, string>;
  risk_score: number;
  risk_tier: RiskTier;
  verdict: Verdict;
  routing_decision: RoutingDecision;
  explanation: ScoreExplanation;
  model_version: string;
  tenant_id: string | null;
}

export interface VerdictRequest {
  email_id: string;
  action: VerdictAction;
  reason?: string;
  analyst_id?: string;
}

export interface ApiResponse<T> {
  success: boolean;
  data: T;
  meta?: Record<string, unknown>;
}

export interface ApiError {
  success: false;
  message: string;
  code: string;
}
