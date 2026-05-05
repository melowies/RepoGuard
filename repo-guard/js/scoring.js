import { SCORE_RANGES } from "./data.js";

export function normalizeScore(score) {
  const parsedScore = Number(score);

  if (Number.isNaN(parsedScore)) {
    return 0;
  }

  return Math.min(100, Math.max(0, Math.round(parsedScore)));
}

export function getScoreState(score) {
  const normalizedScore = normalizeScore(score);
  const range = SCORE_RANGES.find((item) => normalizedScore >= item.min && normalizedScore <= item.max);

  return {
    ...range,
    score: normalizedScore
  };
}
