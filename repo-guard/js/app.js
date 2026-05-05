const repoForm = document.querySelector("#repoForm");
const repoUrl = document.querySelector("#repoUrl");
const submitButton = document.querySelector("#submitButton");
const speechBubble = document.querySelector("#speechBubble");
const appShell = document.querySelector("#appShell");
const searchView = document.querySelector("#searchView");
const loadingView = document.querySelector("#loadingView");
const loadingRepoUrl = document.querySelector("#loadingRepoUrl");
const resultView = document.querySelector("#resultView");
const reportView = document.querySelector("#reportView");
const attackView = document.querySelector("#attackView");
const openAttackButton = document.querySelector("#openAttackButton");
const attackActionsBox = document.querySelector("#attackActions");
const attackOutput = document.querySelector("#attackOutput");
const resultMascot = document.querySelector("#resultMascot");
const resultScore = document.querySelector("#resultScore");
const resultStatus = document.querySelector("#resultStatus");
const resultSuccessText = document.querySelector("#resultSuccessText");
const resultDecisionBadge = document.querySelector("#resultDecisionBadge");
const resultRepoName = document.querySelector("#resultRepoName");
const resultRepoUrl = document.querySelector("#resultRepoUrl");
const resultChecks = document.querySelector("#resultChecks");
const resultPositiveMessage = document.querySelector("#resultPositiveMessage");
const resultSpeechBubble = document.querySelector(".result-speech-bubble");
const resultReportButton = document.querySelector(".result-report-button");
const reportSummaryGrid = document.querySelector(".report-summary-grid");
const findingsList = document.querySelector(".findings-list");
const securityNoteBox = document.querySelector(".security-note-box");
const actionsBox = document.querySelector(".actions-box");

const defaultButtonText = "Güvenlik Taramasını Başlat";
const defaultLoadingUrl = "secure-demo-repo";
const defaultSpeechText = "Repo'nu buraya yazalım mı?";
const resultSpeechTextByTone = {
  safe: "Bu repo gayet güvende!",
  danger: "Dur! Önce kritik bulguları temizleyelim.",
  attention: "Bazı noktaları toparlayalım, olur mu?",
  controlled: "Bir bakalım... bazı noktaları kontrol edelim!",
};
const resultStateClasses = ["result-safe", "result-controlled", "result-attention", "result-danger"];
const apiBase = getApiBase();
const scanEndpoint = `${apiBase}/api/scan`;
const healthEndpoint = `${apiBase}/api/health`;
const attackEndpoint = `${apiBase}/api/attack`;
const resetAttackEndpoint = `${apiBase}/api/reset`;

const mascotImages = {
  safe: "assets/bunnies/result-bunny-shield.png",
  danger: "assets/bunnies/danger-bunny-foreground.png",
  attention: "assets/bunnies/attention-bunny-foreground.png",
  controlled: "assets/bunnies/controlled-bunny-foreground.png",
};

const scoreBands = [
  {
    min: 0,
    max: 24,
    tone: "danger",
    status: "Kritik Risk",
    decision: "BLOKE",
    statusSubtitle: "Yayın süreci devam etmemeli",
    speech: resultSpeechTextByTone.danger,
    mascot: mascotImages.danger,
    mascotAlt: "RepoGuard kritik risk durumu",
    positiveMessage:
      "RepoGuard yayını engelleyen risk buldu. En yüksek öncelikli bulguları düzelt, yayını yeniden oluştur ve tekrar tara.",
    recommendationHighlight: "yayını engelleyen risk",
  },
  {
    min: 25,
    max: 49,
    tone: "attention",
    status: "Düzeltme Gerekli",
    decision: "DÜZELT",
    statusSubtitle: "Bazı kontroller iyileştirme istiyor",
    speech: resultSpeechTextByTone.attention,
    mascot: mascotImages.attention,
    mascotAlt: "RepoGuard dikkat durumu",
    positiveMessage:
      "Bu repo yayından önce düzeltilmeli. Raporu incele, düzeltmelerden sonra taramayı yeniden çalıştır.",
    recommendationHighlight: "düzeltilmeli",
  },
  {
    min: 50,
    max: 74,
    tone: "controlled",
    status: "İnceleme Gerekli",
    decision: "İNCELE",
    statusSubtitle: "Manuel kontrol önerilir",
    speech: resultSpeechTextByTone.controlled,
    mascot: mascotImages.controlled,
    mascotAlt: "RepoGuard inceleme durumu",
    positiveMessage:
      "Repo kullanılabilir bir temele sahip, ama güvenlik raporu dikkatli incelenmeli.",
    recommendationHighlight: "dikkatli incelenmeli",
  },
  {
    min: 75,
    max: 100,
    tone: "safe",
    status: "Onaylandı",
    decision: "ONAY",
    statusSubtitle: "Tarama kontrolleri geçti",
    speech: resultSpeechTextByTone.safe,
    mascot: mascotImages.safe,
    mascotAlt: "RepoGuard güvenli durum",
    positiveMessage:
      "RepoGuard taramasında yayını engelleyen bir sorun bulmadı. Yayın imzalamayı ve bağımlılık takibini sürdür.",
    recommendationHighlight: "taramasında",
  },
];

const defaultResultData = {
  score: 92,
  repoUrl: defaultLoadingUrl,
  repoName: "secure-demo-repo",
};

const defaultAttackActions = {
  "tamper-release": "Yayın dosyasını değiştir",
  "leak-secret": "Gizli bilgi ekle",
  "risky-workflow": "Riskli otomasyon ekle",
  "break-signature": "İmzayı boz",
};
const attackActions = { ...defaultAttackActions };

const demoRepoScenarios = {
  "secure-demo-repo": {
    label: "Güvenli demo",
    result: {
      score: 94,
      positiveMessage:
        "RepoGuard bu repoda yayını engelleyen bir sorun bulmadı. Yayın imzalamayı ve bağımlılık takibini sürdür.",
      recommendationHighlight: "sorun bulmadı",
      checks: [
        { label: "Gizli Bilgi", status: "Temiz", icon: "search", tone: "safe", marker: "check" },
        { label: "Bağımlılıklar", status: "Temiz", icon: "gear", tone: "safe", marker: "check" },
        { label: "Otomasyon", status: "Güvenli", icon: "branch", tone: "safe", marker: "check" },
        { label: "Yayın", status: "Doğrulandı", icon: "document", tone: "safe", marker: "check" },
      ],
    },
    report: buildDemoReport("secure-demo-repo", 94, "APPROVED"),
  },
  "review-demo-repo": {
    label: "Kontrol demo",
    result: {
      score: 68,
      positiveMessage: "Repo kullanılabilir bir temele sahip, ama imza ve otomasyon notları dikkatli incelenmeli.",
      recommendationHighlight: "dikkatli incelenmeli",
      checks: [
        { label: "SHA-256", status: "Geçti", icon: "fingerprint", tone: "safe", marker: "check" },
        { label: "Dijital İmza", status: "Kontrol Et", icon: "document", tone: "controlled", marker: "alert" },
        { label: "Gizli Bilgi", status: "İzlenmeli", icon: "search", tone: "attention", marker: "alert" },
        { label: "Otomasyon", status: "Gözden Geçir", icon: "branch", tone: "controlled", marker: "alert" },
      ],
    },
    report: buildDemoReport("review-demo-repo", 68, "REVIEW", {
      cicd: [
        {
          workflow_file: ".github/workflows/release.yml",
          line_number: 14,
          detected_config: "pull_request_target kullanımı",
          risk_level: "medium",
          why_it_matters: "Güvenilmeyen katkıların yayın hattında çalışması dikkat gerektirir.",
          recommendation: "Otomasyon tetikleyicisini daralt ve yayın işlerini manuel onaya bağla.",
        },
      ],
    }),
  },
  "cleanup-demo-repo": {
    label: "Toparlanacak demo",
    result: {
      score: 42,
      positiveMessage: "Bu repo yayından önce toparlanmalı. Bağımlılık ve secret uyarılarını temizledikten sonra tekrar tara.",
      recommendationHighlight: "toparlanmalı",
      checks: [
        { label: "Gizli Bilgi", status: "Uyarı", icon: "search", tone: "attention", marker: "alert" },
        { label: "Bağımlılıklar", status: "Güncelle", icon: "gear", tone: "attention", marker: "alert" },
        { label: "Otomasyon", status: "Sıkılaştır", icon: "branch", tone: "controlled", marker: "alert" },
        { label: "Yayın", status: "İzlemede", icon: "document", tone: "controlled", marker: "alert" },
      ],
    },
    report: buildDemoReport("cleanup-demo-repo", 42, "REVIEW", {
      secrets: [
        {
          file_path: "src/config.js",
          line_number: 18,
          secret_type: "API key",
          severity: "medium",
          entropy_score: 4.2,
          masked_preview: "API_KEY = \"****\"",
          reason: "Demo anahtar benzeri bir değer bulundu.",
          recommendation: "Değeri ortam değişkeni veya gizli bilgi yöneticisi üzerinden yükle.",
        },
      ],
      dependencies: [
        {
          file_path: "package-lock.json",
          ecosystem: "npm",
          package_name: "lodash",
          current_version: "4.17.19",
          recommended_fixed_version: "4.17.21",
          severity: "medium",
          reason: "Bilinen güvenlik açığı olan paket sürümü.",
        },
      ],
    }),
  },
  "critical-demo-repo": {
    label: "Kritik demo",
    result: {
      score: 12,
      positiveMessage:
        "RepoGuard yayını engelleyen kritik risk buldu. Gizli bilgi, imza ve otomasyon bulgularını düzeltmeden yayın sürecini sürdürme.",
      recommendationHighlight: "kritik risk",
      checks: [
        { label: "Gizli Bilgi", status: "Kritik", icon: "search", tone: "danger", marker: "x" },
        { label: "Bağımlılıklar", status: "Riskli", icon: "gear", tone: "danger", marker: "x" },
        { label: "Otomasyon", status: "Yüksek Risk", icon: "branch", tone: "danger", marker: "x" },
        { label: "SHA-256", status: "Başarısız", icon: "fingerprint", tone: "danger", marker: "x" },
        { label: "Dijital İmza", status: "Geçersiz", icon: "document", tone: "danger", marker: "x" },
      ],
    },
    report: buildDemoReport("critical-demo-repo", 12, "BLOCKED", {
      cryptoFailed: true,
      integrityFailed: true,
      secrets: [
        {
          file_path: "src/config.js",
          line_number: 18,
          secret_type: "Kod içi gizli bilgi",
          severity: "critical",
          entropy_score: 7.8,
          masked_preview: "TOKEN = \"ghp_****\"",
          reason: "Kaynak kodda yüksek güvenliğe sahip token deseni bulundu.",
          recommendation: "Token değerini iptal et, geçmiş commitleri temizle ve secret manager kullan.",
        },
      ],
      dependencies: [
        {
          file_path: "requirements.txt",
          ecosystem: "pip",
          package_name: "requests",
          current_version: "2.19.0",
          recommended_fixed_version: "2.32.0",
          severity: "high",
          reason: "Bilinen açık içeren eski paket sürümü.",
        },
      ],
      cicd: [
        {
          workflow_file: ".github/workflows/deploy.yml",
          line_number: 6,
          detected_config: "permissions: write-all",
          risk_level: "high",
          why_it_matters: "Otomasyon gereğinden geniş yazma yetkisiyle çalışıyor.",
          recommendation: "İzinleri job bazında en düşük yetkiye indir.",
        },
      ],
    }),
  },
};

let resetTimer = null;
let currentReport = null;
let currentResultData = null;
let formStatus = null;
let reportExtraPanels = null;

function buildDemoReport(repoSlug, score, releaseStatus, options = {}) {
  const secrets = options.secrets || [];
  const dependencies = options.dependencies || [];
  const cicd = options.cicd || [];
  const cryptoFailed = Boolean(options.cryptoFailed);
  const integrityFailed = Boolean(options.integrityFailed);
  const currentSha = cryptoFailed
    ? "3f64b2f1d045c7e9a44b91ce6f15a2b4d9028ec1a441dd55f0c9221ba47691cf"
    : "af57d3c20d1a88e442f63fd9b0a96756be69f081c91cc8f512a4b7de74ef92d1";
  const storedSha = "af57d3c20d1a88e442f63fd9b0a96756be69f081c91cc8f512a4b7de74ef92d1";
  const currentRoot = integrityFailed
    ? "d0b24ea59d3304af0d5c4f11c2aa8e92375c0773e32e417880f25da173ef14a6"
    : "9f1b0a0cd884fd0a73ad3d9a7f99e62453f2efdd1845eb0b0136bb95108a75a8";
  const expectedRoot = "9f1b0a0cd884fd0a73ad3d9a7f99e62453f2efdd1845eb0b0136bb95108a75a8";

  return {
    security_score: score,
    release_status: releaseStatus,
    repo_source: repoSlug,
    summary: {
      secrets_found: secrets.length,
      vulnerable_dependencies: dependencies.length,
      cicd_risks: cicd.length,
      hash_status: cryptoFailed ? "Failed" : "Passed",
      signature_status: cryptoFailed ? "Invalid" : "Valid",
      merkle_status: integrityFailed ? "Failed" : "Passed",
    },
    findings: {
      secrets,
      dependencies,
      cicd,
      crypto: {
        file_name: "release/app-v1.0.zip",
        hash_match: !cryptoFailed,
        signature_status: cryptoFailed ? "Invalid" : "Valid",
        manifest_signature_status: cryptoFailed ? "Invalid" : "Valid",
        release_status: releaseStatus,
        algorithm: "RSA-PSS-SHA256",
        signed_payload: "release/manifest.json",
        current_sha256: currentSha,
        stored_sha256: storedSha,
        manifest_sha256: storedSha,
        manifest_verification_status: cryptoFailed ? "Invalid manifest signature" : "Valid manifest signature",
        message: cryptoFailed
          ? "Yayın dosyası manifestteki güvenilir hash ve imza verisiyle eşleşmiyor."
          : "Yayın dosyası manifest, SHA-256 ve dijital imza kontrollerinden geçti.",
        manifest: {
          signature_file: "release/manifest.json.sig",
        },
      },
      repository_integrity: {
        root_match: !integrityFailed,
        current_root: currentRoot,
        expected_root: expectedRoot,
        changed_files: integrityFailed ? ["release/app-v1.0.zip", "release/manifest.json"] : [],
        explanation: integrityFailed
          ? "Repo bütünlük referansı beklenen kayıtla eşleşmiyor."
          : "Repo bütünlük referansı beklenen güvenilir kayıtla eşleşiyor.",
      },
    },
    score_breakdown: {
      mode: "dashboard",
      source_penalty: Math.max(0, 100 - score - (cryptoFailed ? 20 : 0)),
      crypto_penalty: cryptoFailed ? 20 : 0,
      total_penalty: Math.max(0, 100 - score),
      strict_security_score: Math.max(0, score - (releaseStatus === "APPROVED" ? 4 : 10)),
      strict_penalties: [
        ...secrets.map((finding) => ({ area: "secret", penalty: 20, severity: finding.severity || "medium" })),
        ...dependencies.map((finding) => ({ area: "dependency", penalty: 12, severity: finding.severity || "medium" })),
        ...cicd.map((finding) => ({ area: "cicd", penalty: 14, severity: finding.risk_level || "medium" })),
        ...(cryptoFailed ? [{ area: "crypto", penalty: 20, severity: "high" }] : []),
        ...(integrityFailed ? [{ area: "repository", penalty: 12, severity: "high" }] : []),
      ],
    },
  };
}

function getDemoScenario(repoAddress) {
  const rawValue = String(repoAddress || "").trim();
  const directKey = rawValue.toLowerCase();
  const slugKey = deriveRepoName(rawValue).toLowerCase();
  const key = demoRepoScenarios[directKey] ? directKey : slugKey;
  const scenario = demoRepoScenarios[key];
  return scenario ? { key, ...scenario } : null;
}

function showDemoScenario(repoAddress) {
  const demo = getDemoScenario(repoAddress);
  if (!demo) {
    return false;
  }

  currentReport = demo.report;
  showFormMessage("", "info");
  showResultScreen({
    repoName: demo.key,
    repoUrl: demo.key,
    ...demo.result,
  });
  return true;
}

function getApiBase() {
  const configured = window.REPOGUARD_API_BASE || "";
  if (configured) {
    return String(configured).replace(/\/$/, "");
  }
  if (window.location.protocol === "file:") {
    return "http://127.0.0.1:8765";
  }
  return "";
}

function normalizeScore(score) {
  const parsedScore = Number(score);
  if (Number.isNaN(parsedScore)) {
    return defaultResultData.score;
  }
  return Math.min(100, Math.max(0, Math.round(parsedScore)));
}

function getScoreBand(score) {
  return scoreBands.find((band) => score >= band.min && score <= band.max) || scoreBands[scoreBands.length - 1];
}

function createElement(tagName, options = {}, children = []) {
  const element = document.createElement(tagName);
  if (options.className) {
    element.className = options.className;
  }
  if (options.text !== undefined) {
    element.textContent = options.text;
  }
  if (options.attrs) {
    Object.entries(options.attrs).forEach(([key, value]) => {
      if (value !== undefined && value !== null) {
        element.setAttribute(key, String(value));
      }
    });
  }
  children.filter(Boolean).forEach((child) => {
    element.append(child instanceof Node ? child : document.createTextNode(String(child)));
  });
  return element;
}

function normalizeSeverity(value) {
  const normalized = String(value || "").trim().toLowerCase();
  if (normalized.includes("critical")) {
    return "critical";
  }
  if (normalized.includes("high") || normalized.includes("invalid") || normalized.includes("mismatch")) {
    return "high";
  }
  if (normalized.includes("medium") || normalized.includes("missing") || normalized.includes("error")) {
    return "medium";
  }
  if (normalized.includes("low")) {
    return "low";
  }
  return "info";
}

function severityToTone(severity) {
  const normalized = normalizeSeverity(severity);
  if (normalized === "critical" || normalized === "high") {
    return "danger";
  }
  if (normalized === "medium") {
    return "attention";
  }
  if (normalized === "low") {
    return "controlled";
  }
  return "safe";
}

function severityRank(severity) {
  return {
    critical: 4,
    high: 3,
    medium: 2,
    low: 1,
    info: 0,
  }[normalizeSeverity(severity)] ?? 0;
}

function highestSeverity(items, fieldName) {
  return (items || []).reduce((current, item) => {
    const next = normalizeSeverity(item?.[fieldName]);
    return severityRank(next) > severityRank(current) ? next : current;
  }, "info");
}

function pluralize(count, singular, plural = `${singular}s`) {
  return count === 1 ? singular : plural;
}

function shortHash(value, length = 12) {
  const text = String(value || "");
  if (!text) {
    return "N/A";
  }
  if (text.length <= length * 2 + 3) {
    return text;
  }
  return `${text.slice(0, length)}...${text.slice(-length)}`;
}

function toRepoDisplayPath(value) {
  const text = String(value || "").trim();
  if (!text) {
    return "";
  }

  const normalized = text.replaceAll("\\", "/");
  const repoMatch = normalized.match(/(?:^|\/)repo\/(.+)$/i);
  if (repoMatch) {
    return repoMatch[1];
  }

  const knownMarkers = ["/release/", "/src/", "/.github/", "/package", "/requirements"];
  const marker = knownMarkers
    .map((item) => ({ item, index: normalized.toLowerCase().lastIndexOf(item) }))
    .filter(({ index }) => index >= 0)
    .sort((left, right) => right.index - left.index)[0];

  if (marker) {
    return normalized.slice(marker.index + 1);
  }
  return normalized;
}

function sanitizeLocalPathsInText(value) {
  const text = String(value || "");
  if (!text) {
    return "";
  }
  return text.replace(/[A-Za-z]:[^\s,;)]+/g, (pathValue) => toRepoDisplayPath(pathValue));
}

function deriveRepoName(repoAddress) {
  try {
    const parsedUrl = new URL(repoAddress);
    const pathParts = parsedUrl.pathname.split("/").filter(Boolean);
    const repoSlug = pathParts[pathParts.length - 1];
    return repoSlug ? repoSlug.replace(/\.git$/i, "") : defaultResultData.repoName;
  } catch {
    const source = String(repoAddress || "").trim();
    if (!source) {
      return defaultResultData.repoName;
    }
    const pathParts = source.split(/[\\/]/).filter(Boolean);
    const repoSlug = pathParts[pathParts.length - 1] || source;
    return repoSlug.replace(/\.git$/i, "");
  }
}

function clearResultStateClasses() {
  appShell.classList.remove(...resultStateClasses);
  resultView.classList.remove(...resultStateClasses);
  document.body.classList.remove(...resultStateClasses);
}

function setResultState(tone) {
  clearResultStateClasses();
  const stateClass = `result-${tone}`;
  appShell.classList.add(stateClass);
  resultView.classList.add(stateClass);
  document.body.classList.add(stateClass);
}

function getStatusTextNode() {
  return resultStatus.querySelector("span");
}

function renderStatusSubtitle(message) {
  resultSuccessText.textContent = String(message || "");
}

function appendHighlightedText(parent, text, highlight) {
  const content = String(text || "");
  if (!highlight || !content.includes(highlight)) {
    parent.append(document.createTextNode(content));
    return;
  }

  const start = content.indexOf(highlight);
  const before = content.slice(0, start);
  const after = content.slice(start + highlight.length);
  parent.append(document.createTextNode(before));

  const highlighted = document.createElement("span");
  highlighted.className = "recommendation-highlight";
  highlighted.textContent = highlight;
  parent.append(highlighted, document.createTextNode(after));
}

function renderRecommendation(message, highlight) {
  const lines = String(message || "")
    .split("\n")
    .filter(Boolean);

  resultPositiveMessage.replaceChildren();

  lines.forEach((line, index) => {
    if (index > 0) {
      resultPositiveMessage.append(document.createElement("br"));
    }
    appendHighlightedText(resultPositiveMessage, line, highlight);
  });
}

function renderChecks(checks = [], fallbackTone = "safe") {
  const checksList = Array.isArray(checks) && checks.length > 0 ? checks : buildDefaultChecks();

  resultChecks.replaceChildren(
    ...checksList.map((check) => {
      const tone = check.tone || fallbackTone;
      const markerType = check.marker || (tone === "safe" || tone === "controlled" ? "check" : "alert");
      const card = createElement("article", { className: `result-check-card tone-${tone}` });

      const icon = createElement("span", {
        className: `check-icon ${check.icon || "search"}-icon`,
        attrs: { "aria-hidden": "true" },
      });

      const label = createElement("h2", { text: check.label || "" });
      const status = createElement("span", { className: `check-status tone-${tone}` });
      const marker = createElement("span", {
        className: `check-status-marker marker-${markerType}`,
        text: markerType === "check" ? "OK" : markerType === "x" ? "X" : "!",
        attrs: { "aria-hidden": "true" },
      });
      const statusText = createElement("span", { text: check.status || "" });

      status.append(marker, statusText);
      card.append(icon, label, status);
      return card;
    })
  );
}

function buildDefaultChecks() {
  return [
    { label: "Gizli Bilgi", status: "Beklemede", icon: "search", tone: "controlled", marker: "alert" },
    { label: "Bağımlılıklar", status: "Beklemede", icon: "gear", tone: "controlled", marker: "alert" },
    { label: "Otomasyon", status: "Beklemede", icon: "branch", tone: "controlled", marker: "alert" },
    { label: "Yayın", status: "Beklemede", icon: "document", tone: "controlled", marker: "alert" },
  ];
}

function resetFeedback() {
  repoForm.classList.remove("is-empty", "is-success");
  submitButton.classList.remove("is-busy");
  submitButton.disabled = false;
  submitButton.querySelector("span:nth-child(2)").textContent = defaultButtonText;
  speechBubble.textContent = defaultSpeechText;
}

function setFormBusy(isBusy) {
  submitButton.disabled = isBusy;
  submitButton.classList.toggle("is-busy", isBusy);
  submitButton.querySelector("span:nth-child(2)").textContent = isBusy ? "Taranıyor" : defaultButtonText;
}

function showFormMessage(message, tone = "info") {
  if (!formStatus) {
    return;
  }
  formStatus.hidden = !message;
  formStatus.textContent = message || "";
  formStatus.className = `form-status form-status-${tone}`;
}

function showEmptyFeedback() {
  window.clearTimeout(resetTimer);
  repoForm.classList.remove("is-success");
  repoForm.classList.add("is-empty");
  speechBubble.textContent = "Önce repo kaynağını yazalım.";
  showFormMessage("Repo kaynağı gerekli.", "error");
  repoUrl.focus();

  resetTimer = window.setTimeout(() => {
    repoForm.classList.remove("is-empty");
  }, 420);
}

function showLoadingScreen(repoAddress = defaultLoadingUrl) {
  const analyzedUrl = String(repoAddress || "").trim() || defaultLoadingUrl;

  window.clearTimeout(resetTimer);
  repoForm.classList.remove("is-empty");
  repoForm.classList.add("is-success");
  setFormBusy(true);
  showFormMessage("", "info");
  loadingRepoUrl.textContent = analyzedUrl;

  clearResultStateClasses();
  appShell.classList.add("is-loading");
  appShell.classList.remove("is-result", "is-report", "is-attack");
  document.body.classList.remove("is-result-view", "is-report-view", "is-attack-view");
  searchView.classList.remove("is-active");
  searchView.hidden = true;
  resultView.classList.remove("is-active");
  resultView.hidden = true;
  reportView.classList.remove("is-active");
  reportView.hidden = true;
  attackView.classList.remove("is-active");
  attackView.hidden = true;
  loadingView.hidden = false;

  window.requestAnimationFrame(() => {
    loadingView.classList.add("is-active");
  });
}

function hideLoadingScreen() {
  loadingView.classList.remove("is-active");
  loadingView.hidden = true;
  resultView.classList.remove("is-active");
  resultView.hidden = true;
  reportView.classList.remove("is-active");
  reportView.hidden = true;
  attackView.classList.remove("is-active");
  attackView.hidden = true;
  searchView.hidden = false;
  searchView.classList.add("is-active");
  appShell.classList.remove("is-loading", "is-result", "is-report", "is-attack");
  clearResultStateClasses();
  document.body.classList.remove("is-result-view", "is-report-view", "is-attack-view");
  resetFeedback();
}

function showScanError(repoAddress, error) {
  hideLoadingScreen();
  repoUrl.value = repoAddress;
  repoForm.classList.add("is-empty");
  speechBubble.textContent = "Tarama servisi bu işlemi tamamlayamadı.";
  showFormMessage(error?.message || "Tarama başarısız oldu. Servisi kontrol edip tekrar dene.", "error");
}

function getQueryResultOverrides() {
  const params = new URLSearchParams(window.location.search);
  const score = params.get("score");
  const repoAddress = params.get("repoUrl") || params.get("repo");
  const repoName = params.get("repoName");
  const overrides = {};

  if (score !== null) {
    overrides.score = normalizeScore(score);
  }
  if (repoAddress) {
    overrides.repoUrl = repoAddress;
  }
  if (repoName) {
    overrides.repoName = repoName;
  }
  return overrides;
}

function showResultScreen(resultData = {}) {
  const score = normalizeScore(resultData.score ?? defaultResultData.score);
  const band = getScoreBand(score);
  const mergedData = {
    ...band,
    ...defaultResultData,
    ...resultData,
    score,
  };
  const tone = mergedData.tone || band.tone;
  const repoAddress = String(mergedData.repoUrl || "").trim() || defaultLoadingUrl;
  const repoName = String(mergedData.repoName || "").trim() || deriveRepoName(repoAddress);

  currentResultData = mergedData;
  window.clearTimeout(resetTimer);
  setFormBusy(false);

  resultScore.textContent = score;
  resultRepoName.textContent = repoName;
  resultRepoUrl.textContent = repoAddress;
  resultMascot.src = mergedData.mascot || band.mascot;
  resultMascot.alt = mergedData.mascotAlt || band.mascotAlt;
  resultStatus.className = `result-status-pill status-${tone}`;
  resultDecisionBadge.className = `result-decision-badge decision-${tone}`;
  resultDecisionBadge.textContent = mergedData.decision || band.decision || "";
  getStatusTextNode().textContent = mergedData.status || band.status;
  resultSpeechBubble.textContent = mergedData.speech || band.speech;

  setResultState(tone);
  renderStatusSubtitle(mergedData.statusSubtitle || band.statusSubtitle);
  renderRecommendation(mergedData.positiveMessage || band.positiveMessage, mergedData.recommendationHighlight);
  renderChecks(mergedData.checks || band.checks, tone);

  loadingView.classList.remove("is-active");
  loadingView.hidden = true;
  searchView.classList.remove("is-active");
  searchView.hidden = true;
  reportView.classList.remove("is-active");
  reportView.hidden = true;
  attackView.classList.remove("is-active");
  attackView.hidden = true;
  resultView.hidden = false;
  appShell.classList.remove("is-loading", "is-report", "is-attack");
  appShell.classList.add("is-result");
  document.body.classList.remove("is-report-view", "is-attack-view");
  document.body.classList.add("is-result-view");

  window.requestAnimationFrame(() => {
    resultView.classList.add("is-active");
  });
}

function showReportScreen() {
  window.clearTimeout(resetTimer);
  setFormBusy(false);

  if (currentReport) {
    renderReport(currentReport);
  } else {
    renderEmptyReport();
  }

  clearResultStateClasses();
  loadingView.classList.remove("is-active");
  loadingView.hidden = true;
  searchView.classList.remove("is-active");
  searchView.hidden = true;
  resultView.classList.remove("is-active");
  resultView.hidden = true;
  attackView.classList.remove("is-active");
  attackView.hidden = true;
  reportView.hidden = false;
  appShell.classList.remove("is-loading", "is-result", "is-attack");
  appShell.classList.add("is-report");
  document.body.classList.remove("is-result-view", "is-attack-view");
  document.body.classList.add("is-report-view");

  window.requestAnimationFrame(() => {
    reportView.classList.add("is-active");
  });
}

function showAttackScreen() {
  window.clearTimeout(resetTimer);
  setFormBusy(false);
  renderAttackIntro();

  clearResultStateClasses();
  loadingView.classList.remove("is-active");
  loadingView.hidden = true;
  searchView.classList.remove("is-active");
  searchView.hidden = true;
  resultView.classList.remove("is-active");
  resultView.hidden = true;
  reportView.classList.remove("is-active");
  reportView.hidden = true;
  attackView.hidden = false;
  appShell.classList.remove("is-loading", "is-result", "is-report");
  appShell.classList.add("is-attack");
  document.body.classList.remove("is-result-view", "is-report-view");
  document.body.classList.add("is-attack-view");

  window.requestAnimationFrame(() => {
    attackView.classList.add("is-active");
  });
}

function showRiskResultScreen(resultData = {}) {
  currentReport = demoRepoScenarios["critical-demo-repo"].report;
  showResultScreen({
    score: 12,
    repoName: "critical-demo-repo",
    repoUrl: "critical-demo-repo",
    ...demoRepoScenarios["critical-demo-repo"].result,
    ...resultData,
  });
}

function showAttentionResultScreen(resultData = {}) {
  currentReport = demoRepoScenarios["cleanup-demo-repo"].report;
  showResultScreen({
    score: 42,
    repoName: "cleanup-demo-repo",
    repoUrl: "cleanup-demo-repo",
    ...demoRepoScenarios["cleanup-demo-repo"].result,
    ...resultData,
  });
}

function showControlledResultScreen(resultData = {}) {
  currentReport = demoRepoScenarios["review-demo-repo"].report;
  showResultScreen({
    score: 67,
    repoName: "review-demo-repo",
    repoUrl: "review-demo-repo",
    ...demoRepoScenarios["review-demo-repo"].result,
    ...resultData,
  });
}

async function scanRepository(repoAddress) {
  const response = await fetchWithTimeout(scanEndpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      repo_source: repoAddress,
      score_mode: "dashboard",
    }),
  });
  const data = await readJsonResponse(response);
  if (!response.ok) {
    throw new Error(data?.error || `Tarama HTTP ${response.status} ile başarısız oldu.`);
  }
  return data?.payload || data;
}

async function fetchWithTimeout(url, options = {}, timeoutMs = 120000) {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } catch (error) {
    if (error.name === "AbortError") {
      throw new Error("Tarama zaman aşımına uğradı. Daha küçük bir repo dene veya tarama servisi kayıtlarını kontrol et.");
    }
    if (window.location.protocol === "file:") {
      throw new Error("Tarama servisine erişilemiyor. Şu komutla başlat: python dashboard.py --serve");
    }
    throw new Error(`Tarama servisine erişilemiyor: ${error.message}`);
  } finally {
    window.clearTimeout(timeout);
  }
}

async function readJsonResponse(response) {
  try {
    return await response.json();
  } catch {
    return {};
  }
}

function mapBackendReportToResult(payload) {
  const score = normalizeScore(payload?.security_score);
  const crypto = payload?.findings?.crypto || {};
  const releaseStatus = String(payload?.release_status || crypto.release_status || "").toUpperCase();
  const cryptoFailed =
    crypto.hash_match === false ||
    (crypto.signature_status && crypto.signature_status !== "Valid") ||
    crypto.repository_integrity_match === false;
  const tone = cryptoFailed ? "danger" : getScoreBand(score).tone;
  const repoAddress = payload?.repo_source || defaultLoadingUrl;
  const decision = releaseStatus || (score >= 80 ? "APPROVED" : "REVIEW");
  const decisionLabel = translateReleaseStatus(decision);

  return {
    score,
    tone,
    repoUrl: repoAddress,
    repoName: deriveRepoName(repoAddress),
    status: decision === "APPROVED" ? "Onaylandı" : tone === "danger" ? "Bloke" : "İnceleme Gerekli",
    decision: decisionLabel,
    statusSubtitle: buildStatusSubtitle(payload),
    speech: resultSpeechTextByTone[tone] || resultSpeechTextByTone.controlled,
    mascot: mascotImages[tone],
    mascotAlt: `RepoGuard ${tone} state illustration`,
    checks: buildOverviewChecks(payload),
    positiveMessage: buildResultMessage(payload),
    recommendationHighlight: decision === "APPROVED" ? "geçti" : "yayın riski",
  };
}

function translateReleaseStatus(value) {
  const normalized = String(value || "").toUpperCase();
  if (normalized === "APPROVED") {
    return "ONAY";
  }
  if (normalized === "BLOCKED") {
    return "BLOKE";
  }
  if (normalized === "REVIEW") {
    return "İNCELE";
  }
  return String(value || "BİLİNMİYOR");
}

function translateStatus(value) {
  const text = String(value || "");
  const normalized = text.toLowerCase();
  if (normalized === "passed" || normalized === "valid" || normalized === "verified") {
    return "Geçti";
  }
  if (normalized === "failed" || normalized === "invalid") {
    return "Başarısız";
  }
  if (normalized === "error") {
    return "Hata";
  }
  if (normalized === "missing") {
    return "Eksik";
  }
  if (normalized === "hash mismatch") {
    return "Parmak izi uyuşmazlığı";
  }
  if (normalized === "critical") {
    return "Kritik";
  }
  if (normalized === "high") {
    return "Yüksek";
  }
  if (normalized === "medium") {
    return "Orta";
  }
  if (normalized === "low") {
    return "Düşük";
  }
  if (normalized === "signature invalid") {
    return "İmza geçersiz";
  }
  if (normalized === "n/a") {
    return "Yok";
  }
  return text;
}

function translateBackendText(value) {
  const text = sanitizeLocalPathsInText(value);
  if (!text) {
    return "";
  }

  const missingFileMatch = text.match(/^Missing (release|manifest|signature) file:\s*(.+)$/i);
  if (missingFileMatch) {
    const labels = {
      release: "yayın dosyası",
      manifest: "manifest dosyası",
      signature: "imza dosyası",
    };
    return `Beklenen ${labels[missingFileMatch[1].toLowerCase()] || "dosya"} eksik: ${toRepoDisplayPath(missingFileMatch[2])}`;
  }

  const exactTranslations = {
    "Demo vulnerable version": "Demo için riskli sürüm",
    "Demo outdated version": "Demo için eski sürüm",
    "Demo outdated framework version": "Demo için eski framework sürümü",
    "Demo outdated HTTP library": "Demo için eski HTTP kütüphanesi",
    "Manifest signature is valid and the signed SHA-256 matches the current release file.":
      "Manifest imzası geçerli ve imzalanan SHA-256 mevcut yayın dosyasıyla eşleşiyor.",
    "The manifest signature does not verify with the trusted public key.":
      "Manifest imzası güvenilen açık anahtar ile doğrulanamıyor.",
    "Every virtual repository file matched the trusted baseline, so the Merkle Root is stable.":
      "Tüm sanal repo dosyaları güvenilen referansla eşleşti; repo bütünlük referansı stabil.",
    "At least one file hash changed, so the Merkle Root no longer matches the trusted baseline.":
      "En az bir dosya parmak izi değişti; repo bütünlük referansı artık güvenilen referansla eşleşmiyor.",
    "Every event hash matches its content and the previous event hash.":
      "Her olay özeti kendi içeriği ve önceki olay özetiyle eşleşiyor.",
    "One logged event was changed after hashing, so the recomputed hash no longer matches the stored currentHash.":
      "Bir kayıt özetleme işleminden sonra değiştirildi; yeniden hesaplanan özet kayıtlı değerle eşleşmiyor.",
    "Hash Mismatch": "Parmak izi uyuşmazlığı",
  };

  if (exactTranslations[text]) {
    return exactTranslations[text];
  }

  const baselineMatch = text.match(/^Baseline scan completed with release status (.+)\.$/);
  if (baselineMatch) {
    return `Referans tarama ${translateReleaseStatus(baselineMatch[1])} yayın durumuyla tamamlandı.`;
  }

  const policyMatch = text.match(/^Policy decision: (.+) with score (.+)\.$/);
  if (policyMatch) {
    return `Politika kararı: ${translateReleaseStatus(policyMatch[1])}, skor ${policyMatch[2]}.`;
  }

  const replacements = [
    ["Regex matched api key naming patterns", "API key adlandırma deseni eşleşti"],
    ["Regex matched password naming patterns", "Parola adlandırma deseni eşleşti"],
    ["Regex matched jwt secret naming patterns", "JWT secret adlandırma deseni eşleşti"],
    ["Regex matched token naming patterns", "Token adlandırma deseni eşleşti"],
    ["value has token-like entropy", "değer token benzeri entropiye sahip"],
    ["credential type could grant direct access if it were real", "gerçek olsaydı bu kimlik bilgisi doğrudan erişim sağlayabilirdi"],
    ["Remove the secret from source code, rotate the key, and use environment variables or a secret manager.", "Gizli değeri kaynak koddan kaldır, anahtarı yenile ve ortam değişkeni ya da gizli bilgi yöneticisi kullan."],
    ["Remove the password from source code, rotate it, and load it from a protected secret store.", "Parolayı kaynak koddan kaldır, yenile ve korumalı gizli bilgi deposu üzerinden yükle."],
    ["The pull_request_target trigger runs in the base repository context and can be risky when untrusted pull request code is handled incorrectly.", "pull_request_target tetikleyicisi ana repo bağlamında çalışır; güvenilmeyen katkı isteği kodu hatalı ele alınırsa risklidir."],
    ["Use pull_request for untrusted code, or carefully isolate checkout, scripts, and secrets when pull_request_target is required.", "Güvenilmeyen kod için pull_request kullan; pull_request_target gerekiyorsa kod çekme, komut dosyası ve gizli bilgi erişimini dikkatle izole et."],
    ["The workflow has excessive repository permissions. If compromised, it may modify repository contents or releases.", "Otomasyon aşırı repo iznine sahip. Ele geçirilirse repo içeriğini veya yayınları değiştirebilir."],
    ["Use least privilege permissions, for example permissions: contents: read.", "En düşük yetki izinleri kullan; örneğin permissions: contents: read."],
    ["Deployment, release, or publishing jobs can affect production artifacts; broad permissions make compromise more damaging.", "Dağıtım, yayın veya paketleme işleri üretim çıktısını etkileyebilir; geniş izinler ele geçirilme etkisini büyütür."],
    ["Move deploy and release jobs to the smallest possible permission set and require environment approvals for sensitive deployments.", "Dağıtım ve yayın işlerini mümkün olan en dar izin setine taşı ve hassas dağıtımlar için ortam onayı zorunlu kıl."],
    ["A hardcoded secret in a workflow can be exposed to logs, pull requests, or compromised jobs.", "Otomasyon içindeki kod içine yazılmış gizli değer loglara, katkı isteklerine veya ele geçirilmiş işlere sızabilir."],
    ["Remove the hardcoded value, rotate it if it was real, and store it in GitHub Actions secrets or an external secret manager.", "Kod içine yazılmış değeri kaldır, gerçekse yenile ve GitHub Actions gizli bilgileri ya da harici gizli bilgi yöneticisi içinde sakla."],
    ["The action is pinned to the moving master branch, so its behavior can change unexpectedly.", "Action hareketli master dalına bağlı; davranışı beklenmedik şekilde değişebilir."],
    ["Pin actions to a version tag such as @v4 or to a full commit SHA.", "Action sürümlerini @v4 gibi sürüm etiketine veya tam commit SHA değerine sabitle."],
  ];

  return replacements.reduce((current, [source, target]) => current.replaceAll(source, target), text);
}

function buildStatusSubtitle(payload) {
  const summary = payload?.summary || {};
  const parts = [
    `Gizli bilgi ${summary.secrets_found ?? 0}`,
    `Bağımlılık ${summary.vulnerable_dependencies ?? 0}`,
    `Otomasyon ${summary.cicd_risks ?? 0}`,
    `İmza ${translateStatus(summary.signature_status || "N/A")}`,
  ];
  return parts.join(" / ");
}

function buildResultMessage(payload) {
  const allFindings = buildAllFindings(payload);
  if (String(payload?.release_status || "").toUpperCase() === "APPROVED" && allFindings.length === 0) {
    return "Tüm tarama kontrolleri geçti: gizli bilgi, bağımlılık, otomasyon, dosya parmak izi, imza, manifest ve repo bütünlüğü.";
  }
  const top = allFindings.find((finding) => severityRank(finding.severity) >= 3);
  if (top) {
    return `RepoGuard ${top.category} alanında yayın riski buldu: ${top.title}. Düzeltme adımları için ayrıntılı raporu aç.`;
  }
  return "RepoGuard inceleme gerektiren bulgular buldu. Açıklama, kanıt ve aksiyonlar için ayrıntılı raporu aç.";
}

function buildOverviewChecks(payload) {
  const summary = payload?.summary || {};
  const findings = payload?.findings || {};
  const secrets = findings.secrets || [];
  const dependencies = findings.dependencies || [];
  const cicd = findings.cicd || [];
  const crypto = findings.crypto || {};
  const integrity = findings.repository_integrity || {};

  return [
    countCheck("Gizli Bilgi", summary.secrets_found ?? secrets.length, highestSeverity(secrets, "severity"), "search"),
    countCheck(
      "Bağımlılıklar",
      summary.vulnerable_dependencies ?? dependencies.length,
      highestSeverity(dependencies, "severity"),
      "gear"
    ),
    countCheck("Otomasyon", summary.cicd_risks ?? cicd.length, highestSeverity(cicd, "risk_level"), "branch"),
    statusCheck("SHA-256", crypto.hash_match === true, summary.hash_status || "Failed", "fingerprint"),
    statusCheck("Dijital İmza", crypto.signature_status === "Valid", crypto.signature_status || "Error", "document"),
    statusCheck("Repo Bütünlüğü", integrity.root_match === true, summary.merkle_status || "Failed", "document"),
  ];
}

function countCheck(label, count, severity, icon) {
  const numericCount = Number(count) || 0;
  const tone = numericCount === 0 ? "safe" : severityToTone(severity);
  return {
    label,
    status: numericCount === 0 ? "Temiz" : `${numericCount} ${pluralize(numericCount, "bulgu", "bulgu")}`,
    icon,
    tone,
    marker: numericCount === 0 ? "check" : tone === "danger" ? "x" : "alert",
  };
}

function statusCheck(label, passed, status, icon) {
  return {
    label,
    status: translateStatus(status || (passed ? "Passed" : "Failed")),
    icon,
    tone: passed ? "safe" : "danger",
    marker: passed ? "check" : "x",
  };
}

function renderReport(payload) {
  ensureReportPanels();
  const allFindings = buildAllFindings(payload);
  const affectedFiles = collectAffectedFiles(payload, allFindings);

  renderReportSummary(payload, allFindings, affectedFiles.size);
  renderFindings(allFindings);
  renderFeaturePanels(payload);
  renderSecurityNote(payload);
  renderRecommendedActions(payload, allFindings);
}

function renderReportSummary(payload, allFindings, affectedFileCount) {
  const score = normalizeScore(payload?.security_score);
  const releaseStatus = String(payload?.release_status || "UNKNOWN");
  const findingCount = allFindings.length;
  const overview = buildReportOverview(payload, allFindings);
  reportSummaryGrid.replaceChildren(
    reportOverviewCard(overview),
    reportSummaryCard("summary-score", "Güvenlik puanı", `${score}/100`, "P"),
    reportSummaryCard(
      "summary-status",
      "Sonuç",
      reportReleaseLabel(releaseStatus),
      releaseStatus === "APPROVED" ? "O" : releaseStatus === "BLOCKED" ? "!" : "?"
    ),
    reportSummaryCard("summary-open", "Açık sorun", String(findingCount), "!"),
    reportSummaryCard("summary-files", "Etkilenen dosya", String(affectedFileCount), "D")
  );
}

function buildReportOverview(payload, allFindings) {
  const score = normalizeScore(payload?.security_score);
  const releaseStatus = String(payload?.release_status || "UNKNOWN");
  const tone = getReportTone(score, releaseStatus, allFindings);
  const topFinding = allFindings[0];
  const labels = {
    safe: {
      title: "Repo güvenli görünüyor",
      body: "Tarama, yayını durduracak açık bir sorun bulmadı. Yine de paket güncellemelerini ve yayın imzasını düzenli kontrol etmeye devam et.",
    },
    controlled: {
      title: "Repo yayın öncesi gözden geçirilmeli",
      body: "Genel tablo yönetilebilir görünüyor, ancak bazı noktalar insan kontrolü istiyor. Bulguları sırayla inceleyip tekrar tarama yapman iyi olur.",
    },
    attention: {
      title: "Repo yayından önce düzeltilmeli",
      body: "Tarama, kötüye kullanılabilecek riskler buldu. Önce yüksek riskli sorunları kapat, ardından taramayı yeniden çalıştır.",
    },
    danger: {
      title: "Yayın için güvenli değil",
      body: "RepoGuard yayını durdurabilecek kritik riskler buldu. Bu repoyu düzeltmeler tamamlanmadan canlı ortama taşımamalısın.",
    },
  };
  const selected = labels[tone] || labels.controlled;
  const warning = topFinding
    ? `Öne çıkan uyarı: ${topFinding.title || topFinding.category}.`
    : "Öne çıkan uyarı yok. Rapor temiz görünüyor.";

  return {
    tone,
    score,
    status: reportReleaseLabel(releaseStatus),
    title: selected.title,
    body: selected.body,
    warning,
  };
}

function getReportTone(score, releaseStatus, allFindings = []) {
  const normalizedReleaseStatus = String(releaseStatus || "").toUpperCase();
  const highestRank = allFindings.reduce(
    (current, finding) => Math.max(current, severityRank(finding.severity)),
    0
  );

  if (normalizedReleaseStatus === "BLOCKED" || highestRank >= 4 || score < 25) {
    return "danger";
  }
  if (highestRank >= 3 || score < 50) {
    return "attention";
  }
  if (normalizedReleaseStatus === "REVIEW" || highestRank > 0 || score < 75) {
    return "controlled";
  }
  return "safe";
}

function reportReleaseLabel(value) {
  const normalized = String(value || "").toUpperCase();
  if (normalized === "APPROVED") {
    return "Yayınlanabilir";
  }
  if (normalized === "BLOCKED") {
    return "Yayınlama";
  }
  if (normalized === "REVIEW") {
    return "İncele";
  }
  return "Bilinmiyor";
}

function reportOverviewCard(overview) {
  return createElement("article", { className: `report-overview-card tone-${overview.tone}` }, [
    createElement("div", { className: "report-overview-copy" }, [
      createElement("p", { className: "report-overview-kicker", text: "Genel durum" }),
      createElement("h2", { text: overview.title }),
      createElement("p", { className: "report-overview-body", text: overview.body }),
      createElement("p", { className: "report-overview-warning", text: overview.warning }),
    ]),
    createElement("div", { className: "report-overview-score" }, [
      createElement("span", { text: "Puan" }),
      createElement("strong", { text: `${overview.score}/100` }),
      createElement("em", { text: overview.status }),
    ]),
  ]);
}

function simplifyWorkflowTitle(value) {
  const normalized = String(value || "").toLowerCase();
  if (normalized.includes("permissions") && normalized.includes("write")) {
    return "Otomasyon izni gereğinden geniş";
  }
  if (normalized.includes("pull_request_target")) {
    return "Katkı isteği otomasyonu dikkat istiyor";
  }
  if (normalized.includes("secret")) {
    return "Otomasyonda gizli bilgi riski var";
  }
  if (normalized.includes("@master") || normalized.includes("@main")) {
    return "Kullanılan action sürümü sabit değil";
  }
  return "Otomasyon ayarı gözden geçirilmeli";
}

function reportSummaryCard(className, label, value, iconText) {
  const icon = createElement("span", {
    className: "report-summary-icon metric-letter",
    text: iconText,
    attrs: { "aria-hidden": "true" },
  });
  const labelNode = createElement("p", { text: label });
  const valueNode = createElement("strong", { text: value });
  return createElement("article", { className: `report-summary-card ${className}` }, [
    icon,
    createElement("div", {}, [labelNode, valueNode]),
  ]);
}

function buildAllFindings(payload) {
  const findings = payload?.findings || {};
  const crypto = findings.crypto || {};
  const integrity = findings.repository_integrity || {};
  const allFindings = [];

  (findings.secrets || []).forEach((finding) => {
    allFindings.push({
      kind: "secret",
      category: "Gizli bilgi",
      severity: normalizeSeverity(finding.severity),
      icon: "finding-secret-icon",
      location: finding.file_path || "repo",
      title: "Gizli anahtar kod içinde bulundu",
      meta: `Satır ${finding.line_number || "N/A"} / tür ${finding.secret_type || "bilinmiyor"}`,
      code: finding.masked_preview,
      explanation:
        "Kodun içinde parola, token veya API anahtarı gibi saklanması gereken bir değer görünüyor.",
      whyItMatters:
        "Bu değer gerçekse, repo erişimi olan biri sistemlere veya servis hesaplarına izinsiz erişebilir.",
      recommendation: translateBackendText(finding.recommendation),
      technicalDetails: [
        ["Gizli bilgi türü", finding.secret_type || "N/A"],
        ["Satır", finding.line_number || "N/A"],
        ["Entropi skoru", finding.entropy_score ?? "N/A"],
        ["Tarama açıklaması", translateBackendText(finding.reason) || "N/A"],
      ],
    });
  });

  (findings.dependencies || []).forEach((finding) => {
    allFindings.push({
      kind: "dependency",
      category: "Bağımlılık",
      severity: normalizeSeverity(finding.severity),
      icon: "finding-package-icon",
      location: finding.file_path || finding.ecosystem || "bağımlılık dosyası",
      title: `Güncellenmesi gereken paket: ${finding.package_name || "Paket"}`,
      meta: `Mevcut sürüm ${finding.current_version || "N/A"} / önerilen sürüm ${finding.recommended_fixed_version || "N/A"}`,
      code: translateBackendText(finding.reason),
      explanation: "Projede bilinen güvenlik riski taşıyan eski bir paket sürümü kullanılıyor.",
      whyItMatters:
        "Eski paketler saldırganların hazır güvenlik açıklarını kullanmasına yol açabilir.",
      recommendation: `${finding.package_name || "Paketi"} ${finding.recommended_fixed_version || "desteklenen bir sürüme"} yükselt.`,
      technicalDetails: [
        ["Paket sistemi", finding.ecosystem || "N/A"],
        ["Paket adı", finding.package_name || "N/A"],
        ["Mevcut sürüm", finding.current_version || "N/A"],
        ["Önerilen sürüm", finding.recommended_fixed_version || "N/A"],
        ["Tarama açıklaması", translateBackendText(finding.reason) || "N/A"],
      ],
    });
  });

  (findings.cicd || []).forEach((finding) => {
    allFindings.push({
      kind: "cicd",
      category: "Otomasyon",
      severity: normalizeSeverity(finding.risk_level),
      icon: "finding-workflow-icon",
      location: finding.workflow_file || "otomasyon dosyası",
      title: simplifyWorkflowTitle(finding.detected_config),
      meta: `Satır ${finding.line_number || "N/A"}`,
      code: finding.detected_config,
      explanation:
        "Repo otomasyonunda gereğinden geniş izin veya dikkat isteyen bir çalışma ayarı bulundu.",
      whyItMatters: translateBackendText(finding.why_it_matters),
      recommendation: translateBackendText(finding.recommendation),
      technicalDetails: [
        ["Otomasyon dosyası", finding.workflow_file || "N/A"],
        ["Satır", finding.line_number || "N/A"],
        ["Tespit edilen ayar", finding.detected_config || "N/A"],
        ["Teknik açıklama", translateBackendText(finding.why_it_matters) || "N/A"],
      ],
    });
  });

  if (crypto.hash_match === false) {
    allFindings.push({
      kind: "release",
      category: "Yayın dosyası",
      severity: "high",
      icon: "finding-archive-icon",
      location: toRepoDisplayPath(crypto.file_name) || "yayın dosyası",
      title: "Yayın dosyası beklenen dosyayla eşleşmiyor",
      meta: `Mevcut ${shortHash(crypto.current_sha256)} / beklenen ${shortHash(crypto.stored_sha256)}`,
      code: translateBackendText(crypto.message),
      explanation: "Yayınlanan dosyanın parmak izi, güvenilir kayıtla aynı değil.",
      whyItMatters:
        "Bu durum dosyanın değişmiş, bozulmuş veya yanlış dosyanın yayınlanmış olabileceğini gösterir.",
      recommendation: "Yayın dosyasını yeniden oluştur, manifesti yenile ve düzeltilmiş manifesti imzala.",
      technicalDetails: [
        ["Mevcut SHA-256", shortHash(crypto.current_sha256, 16)],
        ["Beklenen SHA-256", shortHash(crypto.stored_sha256, 16)],
        ["Tarama mesajı", translateBackendText(crypto.message) || "N/A"],
      ],
    });
  }

  if (crypto.signature_status && crypto.signature_status !== "Valid") {
    allFindings.push({
      kind: "signature",
      category: "İmza",
      severity: normalizeSeverity(crypto.signature_status),
      icon: "finding-archive-icon",
      location: toRepoDisplayPath(crypto.manifest?.signature_file || `${crypto.file_name || "release"}.sig`),
      title: "Yayın imzası doğrulanamadı",
      meta: crypto.algorithm || "RSA-PSS-SHA256",
      code: translateBackendText(crypto.message),
      explanation: "Yayın dosyasının güvenilir kişi veya süreç tarafından imzalandığı kanıtlanamıyor.",
      whyItMatters:
        "İmza geçersizse kullanıcılar doğru dosyayı aldığından emin olamaz.",
      recommendation: "İmzalama anahtarını doğrula, imzayı yeniden üret ve özel anahtarları repo dışında tut.",
      technicalDetails: [
        ["İmza durumu", translateStatus(crypto.signature_status)],
        ["Algoritma", crypto.algorithm || "N/A"],
        ["İmza dosyası", toRepoDisplayPath(crypto.manifest?.signature_file) || "N/A"],
        ["Tarama mesajı", translateBackendText(crypto.message) || "N/A"],
      ],
    });
  }

  if (crypto.manifest_signature_status && crypto.manifest_signature_status !== "Valid") {
    allFindings.push({
      kind: "manifest",
      category: "Manifest",
      severity: normalizeSeverity(crypto.manifest_signature_status),
      icon: "finding-archive-icon",
      location: "release/manifest.json",
      title: "Manifest imzası güven vermiyor",
      meta: `Manifest ${shortHash(crypto.manifest_sha256)}`,
      code: translateBackendText(crypto.manifest_verification_status),
      explanation: "Yayın listesini anlatan manifest dosyasının imzası doğrulanamadı.",
      whyItMatters:
        "Manifest güvenilir değilse hangi dosyanın doğru yayın dosyası olduğu netleşmez.",
      recommendation: "Manifesti mevcut yayın dosyasından yeniden oluştur ve manifest hash değerini imzala.",
      technicalDetails: [
        ["Manifest SHA-256", shortHash(crypto.manifest_sha256, 16)],
        ["Manifest imzası", translateStatus(crypto.manifest_signature_status)],
        ["Doğrulama sonucu", translateBackendText(crypto.manifest_verification_status) || "N/A"],
      ],
    });
  }

  if (integrity.root_match === false) {
    allFindings.push({
      kind: "integrity",
      category: "Repo Bütünlüğü",
      severity: "high",
      icon: "finding-archive-icon",
      location: (integrity.changed_files || []).map(toRepoDisplayPath).join(", ") || "repo referansı",
      title: "Repo beklenen güvenilir hâliyle eşleşmiyor",
      meta: `Mevcut ${shortHash(integrity.current_root)} / beklenen ${shortHash(integrity.expected_root)}`,
      code: translateBackendText(integrity.explanation),
      explanation: "Repo içeriği, daha önce güvenilir kabul edilen referansla aynı görünmüyor.",
      whyItMatters:
        "Beklenmeyen dosya değişiklikleri yayın dosyası veya kritik ayarların değiştirilmiş olabileceğini gösterebilir.",
      recommendation: "Değişen referans dosyalarını incele ve yeni güvenilir referansı yalnızca kod incelemesinden sonra onayla.",
      technicalDetails: [
        ["Mevcut kök", shortHash(integrity.current_root, 16)],
        ["Beklenen kök", shortHash(integrity.expected_root, 16)],
        ["Değişen dosyalar", (integrity.changed_files || []).join(", ") || "Yok"],
        ["Tarama açıklaması", translateBackendText(integrity.explanation) || "N/A"],
      ],
    });
  }

  (payload?.errors || []).forEach((message, index) => {
    allFindings.push({
      kind: "scanner-error",
      category: "Tarayıcı Hatası",
      severity: "high",
      icon: "finding-workflow-icon",
      location: `Tarayıcı ${index + 1}`,
      title: "Tarama aracı bir kontrolü tamamlayamadı",
      meta: "Tarama entegrasyon hatasıyla tamamlandı",
      code: translateBackendText(message),
      explanation: "Raporun bir bölümü teknik hata nedeniyle eksik olabilir.",
      whyItMatters:
        "Eksik tarama sonucu, bazı risklerin henüz görülmemiş olabileceği anlamına gelir.",
      recommendation: "Tarama loglarını kontrol et ve hatayı düzelttikten sonra taramayı yeniden çalıştır.",
      technicalDetails: [["Hata mesajı", translateBackendText(message)]],
    });
  });

  (payload?.warnings || []).forEach((message, index) => {
    allFindings.push({
      kind: "warning",
      category: "Uyarı",
      severity: "medium",
      icon: "finding-workflow-icon",
      location: `Uyarı ${index + 1}`,
      title: "Tarama uyarısı",
      meta: "Engelleyici olmayan tarama uyarısı",
      code: translateBackendText(message),
      explanation: "Tarama tamamlandı, ancak dikkat edilmesi gereken bir not üretti.",
      whyItMatters:
        "Bu uyarı tek başına yayını durdurmayabilir; yine de kapsamın doğru olduğundan emin olmak gerekir.",
      recommendation: "Uyarıyı incele ve tarama kapsamının yeterli olduğunu doğrula.",
      technicalDetails: [["Uyarı mesajı", translateBackendText(message)]],
    });
  });

  return allFindings.sort((left, right) => severityRank(right.severity) - severityRank(left.severity));
}

function collectAffectedFiles(payload, allFindings) {
  const files = new Set();
  allFindings.forEach((finding) => {
    if (
      finding.location &&
      !finding.location.startsWith("Scanner") &&
      !finding.location.startsWith("Warning") &&
      !finding.location.startsWith("Tarayıcı") &&
      !finding.location.startsWith("Uyarı")
    ) {
      files.add(finding.location);
    }
  });
  (payload?.findings?.repository_integrity?.changed_files || []).forEach((fileName) => files.add(fileName));
  return files;
}

function renderFindings(allFindings) {
  if (!allFindings.length) {
    findingsList.replaceChildren(
      createElement("article", { className: "finding-card empty-finding-card" }, [
        createElement("div", { className: "finding-card-header" }, [
          createElement("span", {
            className: "finding-icon finding-clean-icon",
            text: "OK",
            attrs: { "aria-hidden": "true" },
          }),
          createElement("div", { className: "finding-heading" }, [
            createElement("p", { className: "finding-category", text: "Temiz rapor" }),
            createElement("h3", { text: "Açık sorun yok" }),
            createElement("p", {
              className: "finding-location",
              text: "Gizli bilgi, bağımlılık, otomasyon, yayın imzası ve repo bütünlüğü kontrolleri geçti.",
            }),
          ]),
          severityBadge("info"),
        ]),
        createElement("p", {
          className: "finding-plain-summary",
          text: "Bu raporda hemen aksiyon gerektiren bir güvenlik bulgusu görünmüyor.",
        }),
      ])
    );
    return;
  }

  findingsList.replaceChildren(...allFindings.map(renderFindingCard));
}

function renderFindingCard(finding) {
  const severity = normalizeSeverity(finding.severity);
  const card = createElement("article", { className: `finding-card severity-${severity}` });
  const icon = createElement("span", {
    className: `finding-icon ${finding.icon || "finding-workflow-icon"}`,
    attrs: { "aria-hidden": "true" },
  }, [createElement("span", { className: "finding-icon-letter", text: finding.category.slice(0, 1) })]);

  const header = createElement("div", { className: "finding-card-header" }, [
    icon,
    createElement("div", { className: "finding-heading" }, [
      createElement("p", { className: "finding-category", text: finding.category || "Bulgu" }),
      createElement("h3", { text: finding.title || finding.category }),
      createElement("p", { className: "finding-location", text: `Konum: ${finding.location || "belirtilmedi"}` }),
    ]),
    severityBadge(severity),
  ]);

  card.append(
    header,
    createElement("p", {
      className: "finding-plain-summary",
      text: getFindingExplanation(finding),
    }),
    createElement("div", { className: "finding-guidance-grid" }, [
      findingInfoBlock("Neden önemli?", getFindingWhyItMatters(finding)),
      findingInfoBlock("Önerilen adım", getFindingRecommendation(finding)),
    ]),
    findingTechnicalDetails(finding)
  );
  return card;
}

function findingInfoBlock(title, body) {
  return createElement("div", { className: "finding-info-block" }, [
    createElement("span", { text: title }),
    createElement("p", { text: body }),
  ]);
}

function getFindingExplanation(finding) {
  if (finding.explanation) {
    return finding.explanation;
  }
  const explanations = {
    secret: "Kod içinde saklanmaması gereken gizli bir değer bulundu.",
    dependency: "Projede güncellenmesi gereken riskli bir paket var.",
    cicd: "Repo otomasyonunda güvenlik açısından dikkat isteyen bir ayar var.",
    release: "Yayın dosyası güvenilir kayıtla eşleşmiyor.",
    signature: "Yayın imzası doğrulanamıyor.",
    manifest: "Manifest dosyasının imzası güvenilir değil.",
    integrity: "Repo, beklenen güvenilir referansla eşleşmiyor.",
  };
  return explanations[finding.kind] || "Bu bulgu güvenlik açısından incelenmeli.";
}

function getFindingWhyItMatters(finding) {
  if (finding.whyItMatters) {
    return finding.whyItMatters;
  }
  const explanations = {
    secret: "Gizli değerler kötü niyetli kişilerin servis hesaplarına erişmesine neden olabilir.",
    dependency: "Eski paketler bilinen açıklar üzerinden saldırı yüzeyini büyütebilir.",
    cicd: "Otomasyon izinleri genişse, ele geçirilen bir iş akışı repo veya yayın dosyalarını değiştirebilir.",
    release: "Dosya eşleşmiyorsa kullanıcıya yanlış veya değiştirilmiş bir yayın ulaşabilir.",
    signature: "İmza doğrulanamazsa yayın dosyasının güvenilir kaynaktan geldiği kanıtlanamaz.",
    manifest: "Manifest güvenilmezse hangi yayın dosyasının doğru olduğu belirsizleşir.",
    integrity: "Beklenmeyen dosya değişiklikleri tedarik zinciri riskine işaret edebilir.",
  };
  return explanations[finding.kind] || "Bu sorun gözden kaçarsa repo güvenliği yanlış değerlendirilebilir.";
}

function getFindingRecommendation(finding) {
  if (finding.recommendation) {
    return finding.recommendation;
  }
  const recommendations = {
    secret: "Gizli değeri repodan kaldır, değeri yenile ve güvenli bir gizli bilgi deposu kullan.",
    dependency: "Paketi önerilen güvenli sürüme güncelle ve taramayı yeniden çalıştır.",
    cicd: "İzinleri daralt, tetikleyicileri kontrol et ve hassas adımlara manuel onay ekle.",
    release: "Yayın dosyasını yeniden oluştur, manifesti güncelle ve imzayı yenile.",
    signature: "İmzalama anahtarını doğrula, imzayı yeniden üret ve özel anahtarı repo dışında tut.",
    manifest: "Manifesti mevcut yayın dosyasından yeniden oluştur ve tekrar imzala.",
    integrity: "Değişen dosyaları incele; güvenilir referansı yalnızca kod incelemesinden sonra güncelle.",
  };
  return recommendations[finding.kind] || "Bulguyu incele, gerekli düzeltmeyi yap ve taramayı yeniden çalıştır.";
}

function findingTechnicalDetails(finding) {
  const rows = [
    ["Bulgu türü", finding.category || "N/A"],
    ["Konum", finding.location || "N/A"],
    ["Tarama notu", finding.meta || ""],
    ["Maskeli/teknik değer", finding.code || ""],
    ...(finding.technicalDetails || []),
  ].filter(([, value]) => value !== undefined && value !== null && String(value).trim() !== "");

  return createElement("details", { className: "finding-technical-details" }, [
    createElement("summary", { text: "Teknik detayları göster" }),
    createElement(
      "dl",
      { className: "detail-grid" },
      rows.flatMap(([label, value]) => [
        createElement("dt", { text: label }),
        createElement("dd", { text: sanitizeLocalPathsInText(value) }),
      ])
    ),
  ]);
}

function severityBadge(severity) {
  const normalized = normalizeSeverity(severity);
  const label = {
    critical: "Kritik",
    high: "Yüksek",
    medium: "Orta",
    low: "Düşük",
    info: "Bilgi",
  }[normalized] || "Bilgi";
  const marker = {
    critical: "!",
    high: "!",
    medium: "!",
    low: "i",
    info: "i",
  }[normalized] || "i";
  return createElement("span", {
    className: `severity-badge severity-${normalized}-badge`,
    attrs: { "aria-label": `Risk seviyesi: ${label}` },
  }, [
    createElement("span", { text: marker, attrs: { "aria-hidden": "true" } }),
    document.createTextNode(label),
  ]);
}

function ensureReportPanels() {
  if (!reportExtraPanels) {
    reportExtraPanels = createElement("section", {
      className: "report-extra-grid",
      attrs: { id: "reportExtraPanels", "aria-label": "Teknik kanıtlar" },
    });
    securityNoteBox.parentNode.insertBefore(reportExtraPanels, securityNoteBox);
  }
}

function renderFeaturePanels(payload) {
  const crypto = payload?.findings?.crypto || {};
  const integrity = payload?.findings?.repository_integrity || {};
  const scoreBreakdown = payload?.score_breakdown || {};

  reportExtraPanels.replaceChildren(
    detailCard("Teknik yayın kanıtları", translateBackendText(crypto.message) || "Yayın doğrulaması tamamlandı.", [
      ["Yayın dosyası", toRepoDisplayPath(crypto.file_name) || "N/A"],
      ["Dosya parmak izi eşleşmesi", crypto.hash_match === true ? "Geçti" : "Başarısız"],
      ["İmza", translateStatus(crypto.signature_status || "N/A")],
      ["Manifest imzası", translateStatus(crypto.manifest_signature_status || "N/A")],
      ["İmzalanan veri", crypto.signed_payload || "N/A"],
      ["Algoritma", crypto.algorithm || "N/A"],
      ["Mevcut SHA-256", shortHash(crypto.current_sha256, 16)],
      ["Kayıtlı SHA-256", shortHash(crypto.stored_sha256, 16)],
    ]),
    detailCard("Teknik repo bütünlüğü", translateBackendText(integrity.explanation) || "Repo bütünlüğü kontrolü tamamlandı.", [
      ["Bütünlük durumu", integrity.root_match ? "Geçti" : "Başarısız"],
      ["Mevcut kök", shortHash(integrity.current_root, 16)],
      ["Beklenen kök", shortHash(integrity.expected_root, 16)],
      ["Değişen dosyalar", (integrity.changed_files || []).map(toRepoDisplayPath).join(", ") || "Yok"],
    ]),
    scoreBreakdownCard(scoreBreakdown)
  );
}

function detailCard(title, description, rows) {
  return createElement("details", { className: "report-detail-card report-technical-card" }, [
    createElement("summary", { className: "report-detail-summary" }, [
      createElement("span", { text: title }),
      createElement("small", { text: description }),
    ]),
    createElement(
      "dl",
      { className: "detail-grid" },
      rows.flatMap(([label, value]) => [
        createElement("dt", { text: label }),
        createElement("dd", { text: sanitizeLocalPathsInText(value) }),
      ])
    ),
  ]);
}

function scoreBreakdownCard(scoreBreakdown) {
  const penalties = scoreBreakdown.strict_penalties || [];
  const penaltyList = penalties.length
    ? createElement(
        "div",
        { className: "penalty-chip-list" },
        penalties.slice(0, 12).map((penalty) =>
          createElement("span", {
            className: "penalty-chip",
            text: `${translatePenaltyArea(penalty.area)}: -${penalty.penalty} (${translateStatus(penalty.severity)})`,
          })
        )
      )
    : createElement("p", { className: "empty-detail", text: "Sıkı modda puan düşüren kayıt yok." });

  return createElement("details", { className: "report-detail-card report-technical-card" }, [
    createElement("summary", { className: "report-detail-summary" }, [
      createElement("span", { text: "Puanın teknik hesaplaması" }),
      createElement("small", { text: "Merak eden kullanıcılar için puanın nasıl düştüğünü gösterir." }),
    ]),
    createElement("dl", { className: "detail-grid" }, [
      createElement("dt", { text: "Mod" }),
      createElement("dd", { text: scoreBreakdown.mode === "dashboard" ? "ekran modu" : scoreBreakdown.mode || "ekran modu" }),
      createElement("dt", { text: "Kaynak cezası" }),
      createElement("dd", { text: String(scoreBreakdown.source_penalty ?? 0) }),
      createElement("dt", { text: "Kripto cezası" }),
      createElement("dd", { text: String(scoreBreakdown.crypto_penalty ?? 0) }),
      createElement("dt", { text: "Toplam ceza" }),
      createElement("dd", { text: String(scoreBreakdown.total_penalty ?? 0) }),
      createElement("dt", { text: "Sıkı mod skoru" }),
      createElement("dd", { text: `${scoreBreakdown.strict_security_score ?? "N/A"}/100` }),
    ]),
    penaltyList,
  ]);
}

function translatePenaltyArea(value) {
  const normalized = String(value || "").toLowerCase();
  if (normalized === "secret") {
    return "Gizli bilgi";
  }
  if (normalized === "dependency") {
    return "Bağımlılık";
  }
  if (normalized === "cicd") {
    return "Otomasyon";
  }
  if (normalized === "crypto") {
    return "Yayın doğrulaması";
  }
  if (normalized === "repository") {
    return "Repo bütünlüğü";
  }
  return String(value || "Alan");
}

function renderSecurityNote(payload) {
  const crypto = payload?.findings?.crypto || {};
  const integrity = payload?.findings?.repository_integrity || {};
  const noteText =
    `${translateBackendText(crypto.message) || "Yayın doğrulaması tamamlandı."} ` +
    `${translateBackendText(integrity.explanation) || "Repo bütünlüğü değerlendirildi."}`;
  securityNoteBox.replaceChildren(
    createElement("div", { className: "report-info-heading" }, [
      createElement("span", { className: "report-info-icon metric-letter", text: "i", attrs: { "aria-hidden": "true" } }),
      createElement("h2", { text: "Rapor notu" }),
    ]),
    createElement("div", { className: "report-info-content" }, [
      createElement("p", {
        text: noteText,
      }),
      createElement("p", {
        className: "report-info-muted",
        text: "Hassas değerler ekranda gösterilmeden önce maskelenir.",
      }),
    ])
  );
}

function renderRecommendedActions(payload, allFindings) {
  const actions = buildRecommendedActions(payload, allFindings);
  actionsBox.replaceChildren(
    createElement("div", { className: "report-info-heading" }, [
      createElement("span", {
        className: "report-info-icon actions-main-icon metric-letter",
        text: "✓",
        attrs: { "aria-hidden": "true" },
      }),
      createElement("h2", { text: "Önerilen sonraki adımlar" }),
    ]),
    createElement("div", { className: "report-info-content" }, [
      createElement(
        "ul",
        {},
        actions.map((action) => createElement("li", { text: action }))
      ),
    ])
  );
}

function buildRecommendedActions(payload, allFindings) {
  const categories = new Set(allFindings.map((finding) => finding.category));
  const kinds = new Set(allFindings.map((finding) => finding.kind));
  const actions = [];

  if (categories.has("Gizli bilgi") || kinds.has("secret")) {
    actions.push("Kod içindeki gizli bilgileri kaldır, sızmış olabilecek değerleri yenile ve güvenli bir gizli bilgi deposu kullan.");
  }
  if (categories.has("Bağımlılık") || kinds.has("dependency")) {
    actions.push("Riskli paketleri önerilen güvenli sürümlere güncelle.");
  }
  if (categories.has("Otomasyon") || kinds.has("cicd")) {
    actions.push("Otomasyon izinlerini daralt, kullanılan otomasyon bileşeni sürümlerini sabitle ve güvenilmeyen katkı isteği akışlarını izole et.");
  }
  if (categories.has("Yayın dosyası") || categories.has("İmza") || categories.has("Manifest")) {
    actions.push("Yayın dosyasını yeniden oluştur, manifesti yenile ve güvenilen anahtarla imzala.");
  }
  if (categories.has("Repo Bütünlüğü")) {
    actions.push("Yeni güvenilir repo referansını onaylamadan önce değişen dosyaları incele.");
  }
  if (payload?.errors?.length) {
    actions.push("Sonraki raporun kapsamı tam olsun diye tarama hatalarını çöz.");
  }
  if (!actions.length) {
    actions.push("Yayın imzalama, paket güncelleme ve dar otomasyon izni kontrollerini düzenli yayın listende tut.");
  }
  return actions;
}

function renderAttackButtons() {
  if (!attackActionsBox) {
    return;
  }
  attackActionsBox.replaceChildren(
    createElement("button", {
      className: "attack-action-button reset-action",
      text: "Referansı sıfırla",
      attrs: { type: "button", "data-attack-reset": "true" },
    }),
    ...Object.entries(attackActions).map(([value, label]) =>
      createElement("button", {
        className: "attack-action-button",
        text: label,
        attrs: { type: "button", "data-attack-action": value },
      })
    )
  );
}

function renderAttackIntro() {
  if (!attackOutput || attackOutput.childElementCount) {
    return;
  }
  attackOutput.replaceChildren(
    createElement("p", {
      className: "empty-detail",
      text: "Sonucu görmek için bir simülasyon seç.",
    })
  );
}

function setAttackBusy(isBusy) {
  attackActionsBox?.querySelectorAll("button").forEach((button) => {
    button.disabled = isBusy;
    button.classList.toggle("is-busy", isBusy);
  });
}

async function runAttackSimulation(action) {
  if (!attackOutput) {
    return;
  }
  setAttackBusy(true);
  attackOutput.replaceChildren(
    createElement("p", {
      className: "empty-detail",
      text: action ? "Atak simülasyonu çalıştırılıyor..." : "Referans durum sıfırlanıyor...",
    })
  );

  const endpoint = action ? attackEndpoint : resetAttackEndpoint;
  const options = action
    ? {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ attack: action }),
      }
    : { method: "POST" };

  try {
    const response = await fetchWithTimeout(endpoint, options, 120000);
    const payload = await readJsonResponse(response);
    if (!response.ok) {
      throw new Error(payload?.error || `Simülasyon isteği HTTP ${response.status} ile başarısız oldu.`);
    }
    renderAttackResult(payload);
  } catch (error) {
    attackOutput.replaceChildren(
      createElement("div", { className: "attack-error-box" }, [
        createElement("strong", { text: "Simülasyon çalışmadı" }),
        createElement("p", {
          text:
            error?.message ||
            "Tarama servisine ulaşılamadı. Demo servisini başlatıp tekrar deneyebilirsin.",
        }),
      ])
    );
  } finally {
    setAttackBusy(false);
  }
}

function renderAttackResult(payload) {
  const before = payload?.before || {};
  const after = payload?.after || {};
  const audit = payload?.audit_log || {};
  const events = audit.events || [];
  const message =
    translateBackendText(payload?.attack_result?.message || audit.explanation) ||
    "Simülasyon tamamlandı.";

  attackOutput.replaceChildren(
    createElement("div", { className: "mini-status-grid" }, [
      miniStatusCard("Önce", before.security_score, translateReleaseStatus(before.release_status)),
      miniStatusCard("Sonra", after.security_score, translateReleaseStatus(after.release_status)),
      miniStatusCard("Kayıt zinciri", translateStatus(audit.status || "N/A"), audit.valid ? "Geçerli" : "Bozuk"),
    ]),
    createElement("p", { className: "attack-message", text: message }),
    events.length
      ? createElement(
          "ol",
          { className: "audit-event-list" },
          events.map((event) =>
            createElement("li", {
              text: `${translateAuditEvent(event.event)}: ${translateBackendText(event.detail)} (${shortHash(event.current_hash || event.currentHash, 8)})`,
            })
          )
        )
      : createElement("p", {
          className: "empty-detail",
          text: "Bu yanıtta kayıt zinciri olayı bulunmadı.",
        })
  );
}

function miniStatusCard(label, value, status) {
  return createElement("article", { className: "mini-status-card" }, [
    createElement("span", { text: label }),
    createElement("strong", { text: value === undefined || value === null ? "Yok" : String(value) }),
    createElement("p", { text: status || "" }),
  ]);
}

function translateAuditEvent(value) {
  const normalized = String(value || "");
  const labels = {
    baseline_scan: "Referans tarama",
    "tamper-release": "Yayın dosyası değiştirildi",
    "leak-secret": "Gizli bilgi eklendi",
    "risky-workflow": "Riskli otomasyon eklendi",
    "break-signature": "İmza bozuldu",
    policy_decision: "Politika kararı",
  };
  return labels[normalized] || normalized || "Kayıt";
}

function renderEmptyReport() {
  ensureReportPanels();
  reportSummaryGrid.replaceChildren(
    reportOverviewCard({
      tone: "controlled",
      score: "--",
      status: "Taranmadı",
      title: "Henüz rapor oluşturulmadı",
      body: "Ayrıntılı raporu görmek için önce bir repo taraması başlat. Tarama tamamlandığında burada sade özet, bulgular ve teknik kanıtlar görünecek.",
      warning: "Öne çıkan uyarı yok; çünkü henüz tarama sonucu alınmadı.",
    }),
    reportSummaryCard("summary-score", "Güvenlik puanı", "--/100", "P"),
    reportSummaryCard("summary-status", "Sonuç", "Taranmadı", "-"),
    reportSummaryCard("summary-open", "Açık sorun", "0", "!"),
    reportSummaryCard("summary-files", "Etkilenen dosya", "0", "D")
  );
  findingsList.replaceChildren(
    createElement("article", { className: "finding-card empty-finding-card" }, [
      createElement("div", { className: "finding-card-header" }, [
        createElement("span", { className: "finding-icon finding-clean-icon", text: "RG", attrs: { "aria-hidden": "true" } }),
        createElement("div", { className: "finding-heading" }, [
          createElement("p", { className: "finding-category", text: "Bekleniyor" }),
          createElement("h3", { text: "Tarama raporu yok" }),
          createElement("p", {
            className: "finding-location",
            text: "Önce repo taraması çalıştır.",
          }),
        ]),
        severityBadge("info"),
      ]),
      createElement("p", {
        className: "finding-plain-summary",
        text: "Tarama tamamlandığında açık sorunlar burada anlaşılır kartlar halinde listelenecek.",
      }),
    ])
  );
  reportExtraPanels.replaceChildren(
    detailCard("Teknik kontroller", "Tarama tamamlandıktan sonra teknik kanıtlar bu kapalı bölümde gösterilir.", [
      ["Gizli bilgi", "Maskelenmiş önizlemelerle gizli bilgi tespiti"],
      ["Bağımlılıklar", "Bilinen riskli paket sürümleri"],
      ["Otomasyon", "İş akışı izinleri ve tedarik zinciri riskleri"],
      ["Yayın", "Dosya parmak izi, manifest ve imza doğrulaması"],
      ["Bütünlük", "Repo bütünlük referansı denetimi"],
    ])
  );
  renderSecurityNote({});
  renderRecommendedActions({}, []);
}

function ensureSearchControls() {
  repoUrl.type = "text";
  repoUrl.placeholder = "GitHub URL, demo repo adı veya yerel klasör";

  const helperText = document.querySelector(".helper-text");
  if (helperText) {
    helperText.replaceChildren(
      createElement("span", { attrs: { "aria-hidden": "true" } }),
      document.createTextNode("Örnekler: secure-demo-repo, review-demo-repo, cleanup-demo-repo, critical-demo-repo")
    );
  }

  const scanOptions = createElement("div", { className: "scan-options", attrs: { "aria-label": "Tarama kısayolları" } });
  Object.entries(demoRepoScenarios).forEach(([value, scenario]) => {
    scanOptions.append(
      createElement("button", {
        className: "scan-chip",
        text: scenario.label,
        attrs: { type: "button", "data-demo-repo": value },
      })
    );
  });

  formStatus = createElement("p", {
    className: "form-status",
    attrs: { id: "formStatus", "aria-live": "polite", hidden: "true" },
  });

  repoForm.append(scanOptions, formStatus);
}

function hydrateStaticCopy() {
  document.title = "RepoGuard | Repo Güvenlik Analizi";
  speechBubble.textContent = defaultSpeechText;
  submitButton.querySelector("span:nth-child(2)").textContent = defaultButtonText;
  document.querySelector("#loadingTitle").firstChild.textContent = "Repo taranıyor";
  const loadingCopy = document.querySelector(".loading-copy p");
  if (loadingCopy) {
    loadingCopy.textContent = "Gizli bilgi, bağımlılık, otomasyon, dosya parmak izi, imza, manifest ve bütünlük kontrolleri çalışıyor.";
  }
  const reassuranceTitle = document.querySelector(".reassurance-box strong");
  const reassuranceBody = document.querySelector(".reassurance-box p");
  if (reassuranceTitle && reassuranceBody) {
    reassuranceTitle.textContent = "Repo girdisi yalnızca yerel RepoGuard tarama servisine gönderilir.";
    reassuranceBody.textContent = "Bulgular ekrana gelmeden önce maskelenir.";
  }
  resultReportButton.querySelector("span:nth-child(2)").textContent = "Ayrıntılı Raporu Aç";
  resultSpeechBubble.textContent = resultSpeechTextByTone.safe;
  const reportSpeech = document.querySelector(".report-speech-bubble");
  if (reportSpeech) {
    reportSpeech.textContent = "Özet hazır.";
  }
  const reportHeading = document.querySelector(".report-section-heading h2");
  if (reportHeading) {
    reportHeading.textContent = "Bulunan sorunlar";
  }
}

async function loadApiMetadata() {
  try {
    const response = await fetchWithTimeout(healthEndpoint, { method: "GET" }, 8000);
    const payload = await readJsonResponse(response);
    if (!response.ok || !payload?.attack_actions) {
      return;
    }
    Object.keys(attackActions).forEach((key) => delete attackActions[key]);
    Object.entries(payload.attack_actions).forEach(([key, value]) => {
      attackActions[key] = defaultAttackActions[key] || value?.label || translateAuditEvent(key);
    });
    renderAttackButtons();
  } catch {
    return;
  }
}

repoForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  const repoAddress = repoUrl.value.trim();
  if (!repoAddress) {
    showEmptyFeedback();
    return;
  }

  if (showDemoScenario(repoAddress)) {
    return;
  }

  currentReport = null;
  showLoadingScreen(repoAddress);

  try {
    const payload = await scanRepository(repoAddress);
    currentReport = payload;
    showResultScreen(mapBackendReportToResult(payload));
  } catch (error) {
    currentReport = null;
    showScanError(repoAddress, error);
  }
});

repoUrl.addEventListener("input", () => {
  repoForm.classList.remove("is-empty");
  showFormMessage("", "info");
  if (!repoUrl.value.trim()) {
    resetFeedback();
  }
});

repoForm.addEventListener("click", (event) => {
  const demoButton = event.target.closest("[data-demo-repo]");
  if (!demoButton) {
    return;
  }
  repoUrl.value = demoButton.getAttribute("data-demo-repo");
  repoForm.classList.remove("is-empty");
  showDemoScenario(repoUrl.value);
});

resultReportButton.addEventListener("click", () => {
  showReportScreen();
});

openAttackButton?.addEventListener("click", () => {
  showAttackScreen();
});

attackView?.addEventListener("click", (event) => {
  const backButton = event.target.closest("[data-attack-back]");
  const actionButton = event.target.closest("[data-attack-action]");
  const resetButton = event.target.closest("[data-attack-reset]");

  if (backButton) {
    hideLoadingScreen();
  } else if (actionButton) {
    runAttackSimulation(actionButton.getAttribute("data-attack-action"));
  } else if (resetButton) {
    runAttackSimulation("");
  }
});

document.addEventListener("repoGuard:loadingComplete", (event) => {
  showResultScreen({
    repoUrl: event.detail?.repoUrl || defaultLoadingUrl,
    ...getQueryResultOverrides(),
  });
});

hydrateStaticCopy();
ensureSearchControls();
renderAttackButtons();
loadApiMetadata();

const initialParams = new URLSearchParams(window.location.search);
const initialView = initialParams.get("view");
const initialOverrides = getQueryResultOverrides();

if (initialView === "risk" || initialView === "risky") {
  showRiskResultScreen(initialOverrides);
} else if (initialView === "attention" || initialView === "cleanup" || initialView === "fix") {
  showAttentionResultScreen(initialOverrides);
} else if (initialView === "controlled" || initialView === "review" || initialView === "review-needed") {
  showControlledResultScreen(initialOverrides);
} else if (initialView === "result") {
  showResultScreen(initialOverrides);
} else if (initialView === "report" || initialView === "detail" || initialView === "detailed-report") {
  showReportScreen();
} else if (initialView === "attack" || initialView === "atak" || initialView === "simulation" || initialView === "simulasyon") {
  showAttackScreen();
}

window.showLoadingScreen = showLoadingScreen;
window.hideLoadingScreen = hideLoadingScreen;
window.showResultScreen = showResultScreen;
window.showRiskResultScreen = showRiskResultScreen;
window.showAttentionResultScreen = showAttentionResultScreen;
window.showControlledResultScreen = showControlledResultScreen;
window.showReportScreen = showReportScreen;
window.showAttackScreen = showAttackScreen;
