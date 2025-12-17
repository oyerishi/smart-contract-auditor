import { RISK_SCORE_THRESHOLDS, SEVERITY_LEVELS } from '../config/constants';

export interface Vulnerability {
  id?: number;
  type: string;
  title?: string;
  severity: string;
  confidence?: number;
  confidenceScore?: number;
  line?: number;
  lineNumber?: number;
  description?: string;
  codeSnippet?: string;
  recommendation?: string;
  cweId?: string;
  detectionMethod?: string;
  falsePositive?: boolean;
}

/**
 * Calculate overall risk score based on vulnerabilities
 */
export const calculateRiskScore = (vulnerabilities: Vulnerability[]): number => {
  if (!vulnerabilities || vulnerabilities.length === 0) return 0;

  const severityWeights: Record<string, number> = {
    [SEVERITY_LEVELS.CRITICAL]: 100,
    [SEVERITY_LEVELS.HIGH]: 75,
    [SEVERITY_LEVELS.MEDIUM]: 50,
    [SEVERITY_LEVELS.LOW]: 25,
    [SEVERITY_LEVELS.INFO]: 10,
  };

  const totalWeight = vulnerabilities.reduce((sum, vuln) => {
    const weight = severityWeights[vuln.severity] || severityWeights[vuln.severity?.toUpperCase()] || 0;
    const confidenceMultiplier = vuln.confidence || vuln.confidenceScore || 1;
    return sum + (weight * confidenceMultiplier);
  }, 0);

  // Normalize to 0-100 scale and round to 2 decimal places
  const normalizedScore = Math.min(100, (totalWeight / vulnerabilities.length));
  return Math.round(normalizedScore * 100) / 100;
};

/**
 * Get risk level based on score
 */
export const getRiskLevel = (score: number): string => {
  if (score >= RISK_SCORE_THRESHOLDS.CRITICAL) return 'Critical';
  if (score >= RISK_SCORE_THRESHOLDS.HIGH) return 'High';
  if (score >= RISK_SCORE_THRESHOLDS.MEDIUM) return 'Medium';
  if (score >= RISK_SCORE_THRESHOLDS.LOW) return 'Low';
  return 'Minimal';
};

/**
 * Get color class based on severity
 */
export const getSeverityColor = (severity: string): string => {
  const colors: Record<string, string> = {
    [SEVERITY_LEVELS.CRITICAL]: 'text-red-600 bg-red-50',
    [SEVERITY_LEVELS.HIGH]: 'text-orange-600 bg-orange-50',
    [SEVERITY_LEVELS.MEDIUM]: 'text-yellow-600 bg-yellow-50',
    [SEVERITY_LEVELS.LOW]: 'text-blue-600 bg-blue-50',
    [SEVERITY_LEVELS.INFO]: 'text-gray-600 bg-gray-50',
  };
  return colors[severity] || colors[SEVERITY_LEVELS.INFO];
};

/**
 * Group vulnerabilities by severity
 */
export const groupBySeverity = (vulnerabilities: Vulnerability[]) => {
  if (!vulnerabilities) return {};
  return vulnerabilities.reduce((acc, vuln) => {
    const severity = vuln.severity;
    if (!acc[severity]) {
      acc[severity] = [];
    }
    acc[severity].push(vuln);
    return acc;
  }, {} as Record<string, Vulnerability[]>);
};
