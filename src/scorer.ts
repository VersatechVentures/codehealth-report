
import { Finding } from './types';

export interface Score {
  overall: number;
  breakdown: {
    security: number;
    dependencies: number;
    quality: number;
    maintainability: number;
  };
  grade: string;
  hardGateTriggered: boolean;
  profile: 'individual' | 'enterprise';
}

const WEIGHTS = {
  security: 0.4,
  dependencies: 0.25,
  quality: 0.2,
  maintainability: 0.15,
};

function getGrade(score: number): string {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}

export function calculateScore(
  findings: Finding[],
  profile: 'individual' | 'enterprise' = 'individual'
): Score {
  let securityScore = 100;
  let dependencyScore = 100;
  let qualityScore = 100;
  let maintainabilityScore = 100; // Assuming a starting point

  let hardGateTriggered = false;

  for (const finding of findings) {
    const penalty = {
      critical: profile === 'enterprise' ? 50 : 25,
      high: profile === 'enterprise' ? 30 : 15,
      medium: 10,
      low: 5,
      info: 0,
    }[finding.severity];

    if (penalty === undefined) continue;

    switch (finding.type) {
      case 'sast':
      case 'secret':
        securityScore -= penalty;
        if (finding.severity === 'critical') {
          hardGateTriggered = true;
        }
        break;
      case 'sca':
        dependencyScore -= penalty;
        if (finding.severity === 'critical') {
          hardGateTriggered = true;
        }
        break;
      case 'quality':
        qualityScore -= penalty;
        break;
      case 'maintainability':
        maintainabilityScore -= penalty;
        break;
    }
  }

  const scores = {
    security: Math.max(0, securityScore),
    dependencies: Math.max(0, dependencyScore),
    quality: Math.max(0, qualityScore),
    maintainability: Math.max(0, maintainabilityScore),
  };

  const overall =
    scores.security * WEIGHTS.security +
    scores.dependencies * WEIGHTS.dependencies +
    scores.quality * WEIGHTS.quality +
    scores.maintainability * WEIGHTS.maintainability;

  const grade = getGrade(overall);

  const finalScore: Score = {
    overall: Math.round(overall),
    breakdown: scores,
    grade: hardGateTriggered && profile === 'enterprise' ? 'F' : grade,
    hardGateTriggered,
    profile,
  };

  if (hardGateTriggered && profile === 'enterprise') {
      finalScore.overall = Math.min(finalScore.overall, 49); // Cap score if hard gate triggered
  }


  return finalScore;
}
