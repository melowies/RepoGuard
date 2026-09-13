import { CHECK_RESULTS, MASCOT_IMAGES, MESSAGES, STATUS_LABELS } from "./data.js";

const shell = document.querySelector("#appShell");
const statusBadge = document.querySelector("#statusBadge");
const mascotImage = document.querySelector("#mascotImage");
const resultTitle = document.querySelector("#resultTitle");
const resultMessage = document.querySelector("#resultMessage");
const selectedScore = document.querySelector("#selectedScore");
const scoreValue = document.querySelector("#scoreValue");
const meterFill = document.querySelector("#meterFill");
const checksGrid = document.querySelector("#checksGrid");

function setShellState(stateName) {
  shell.className = `app-shell ${stateName}`;
}

function setBadge(label, tone) {
  statusBadge.textContent = label;
  statusBadge.className = `status-badge status-${tone}`;
}

function setMascot(src, alt) {
  mascotImage.src = src;
  mascotImage.alt = alt;
}

function renderChecks(checks) {
  checksGrid.replaceChildren(
    ...checks.map((check) => {
      const card = document.createElement("article");
      card.className = "check-card";

      const title = document.createElement("h3");
      title.className = "check-card-title";
      title.textContent = check.title;

      const value = document.createElement("span");
      value.className = `check-card-value tone-${check.tone}`;
      value.textContent = check.value;

      const detail = document.createElement("p");
      detail.textContent = check.detail;

      card.append(title, value, detail);
      return card;
    })
  );
}

export function updateSliderPreview(score) {
  selectedScore.value = score;
  selectedScore.textContent = score;
}

export function showStart() {
  const message = MESSAGES.start;

  setShellState("is-start");
  setBadge(STATUS_LABELS.start, "search");
  setMascot(MASCOT_IMAGES.search, message.mascotAlt);
  resultTitle.textContent = message.title;
  resultMessage.textContent = message.body;
  scoreValue.textContent = "--";
  meterFill.style.width = "0%";
  renderChecks(CHECK_RESULTS.start);
}

export function showLoading(score) {
  const message = MESSAGES.loading;

  setShellState("is-loading");
  setBadge(STATUS_LABELS.loading, "loading");
  setMascot(MASCOT_IMAGES.loading, message.mascotAlt);
  resultTitle.textContent = message.title;
  resultMessage.textContent = message.body;
  scoreValue.textContent = score;
  meterFill.style.width = `${score}%`;
  renderChecks(CHECK_RESULTS.loading);
}

export function showResult(scoreState) {
  const message = MESSAGES[scoreState.id];

  setShellState(`state-${scoreState.id}`);
  setBadge(scoreState.label, scoreState.tone);
  setMascot(scoreState.mascot, message.mascotAlt);
  resultTitle.textContent = message.title;
  resultMessage.textContent = message.body;
  scoreValue.textContent = scoreState.score;
  meterFill.style.width = `${scoreState.score}%`;
  renderChecks(CHECK_RESULTS[scoreState.id]);
}

export function setBusy(isBusy) {
  const analyzeButton = document.querySelector("#analyzeButton");
  analyzeButton.disabled = isBusy;
  analyzeButton.textContent = isBusy ? "Analyzing" : "Analyze";
}
