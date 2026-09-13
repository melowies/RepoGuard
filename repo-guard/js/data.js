export const DEFAULT_SCORE = 82;
export const ANALYSIS_DELAY_MS = 900;

export const MASCOT_IMAGES = {
  search: "assets/bunnies/search-bunny-foreground.png",
  loading: "assets/bunnies/loading-bunny-foreground.png",
  safe: "assets/bunnies/result-bunny-shield.png",
  controlled: "assets/bunnies/controlled-bunny-foreground.png",
  curious: "assets/bunnies/controlled-bunny-foreground.png",
  caution: "assets/bunnies/attention-bunny-foreground.png",
  danger: "assets/bunnies/danger-bunny-foreground.png"
};

export const STATUS_LABELS = {
  start: "Ready",
  loading: "Analyzing",
  danger: "Critical Risk",
  caution: "Attention",
  controlled: "Review",
  curious: "Review",
  safe: "Secure"
};

export const SCORE_RANGES = [
  {
    id: "danger",
    min: 0,
    max: 24,
    label: STATUS_LABELS.danger,
    mascot: MASCOT_IMAGES.danger,
    tone: "danger"
  },
  {
    id: "caution",
    min: 25,
    max: 49,
    label: STATUS_LABELS.caution,
    mascot: MASCOT_IMAGES.caution,
    tone: "caution"
  },
  {
    id: "controlled",
    min: 50,
    max: 74,
    label: STATUS_LABELS.controlled,
    mascot: MASCOT_IMAGES.controlled,
    tone: "controlled"
  },
  {
    id: "safe",
    min: 75,
    max: 100,
    label: STATUS_LABELS.safe,
    mascot: MASCOT_IMAGES.safe,
    tone: "safe"
  }
];

export const MESSAGES = {
  start: {
    title: "Waiting for analysis",
    body: "RepoGuard is ready to turn the selected security score into a clear visual status.",
    mascotAlt: "RepoGuard mascot waiting for analysis"
  },
  loading: {
    title: "Scanning repository",
    body: "Secrets, dependencies, CI/CD, and integrity checks are being evaluated together.",
    mascotAlt: "RepoGuard mascot while the repository is being scanned"
  },
  danger: {
    title: "Critical Risk",
    body: "This repository should be fixed before release. A hash mismatch, invalid signature, secret exposure, or risky CI/CD setting was detected.",
    mascotAlt: "RepoGuard mascot showing a critical-risk state"
  },
  caution: {
    title: "Attention",
    body: "Some checks raised warnings. Review the findings before release.",
    mascotAlt: "RepoGuard mascot showing an attention state"
  },
  controlled: {
    title: "Review Required",
    body: "The overall state is manageable, but signature, secret, and CI/CD settings should still be reviewed.",
    mascotAlt: "RepoGuard mascot showing a review state"
  },
  safe: {
    title: "Secure",
    body: "The checks are clean. The repository looks healthy for the release pipeline.",
    mascotAlt: "RepoGuard mascot showing a secure state"
  }
};

export const CHECK_RESULTS = {
  start: [
    {
      title: "Secret scanning",
      value: "Pending",
      tone: "search",
      detail: "Token and key patterns will be listed during analysis."
    },
    {
      title: "Dependencies",
      value: "Pending",
      tone: "search",
      detail: "Risky package versions will be summarized for the selected score."
    },
    {
      title: "CI/CD policy",
      value: "Pending",
      tone: "search",
      detail: "Workflow permissions and unsafe commands will be checked."
    },
    {
      title: "Integrity",
      value: "Pending",
      tone: "search",
      detail: "Hash, signature, and manifest signals will be monitored together."
    }
  ],
  loading: [
    {
      title: "Secret scanning",
      value: "Scanning",
      tone: "loading",
      detail: "Searching source files for sensitive-data patterns."
    },
    {
      title: "Dependencies",
      value: "Scanning",
      tone: "loading",
      detail: "Comparing package versions with known risks."
    },
    {
      title: "CI/CD policy",
      value: "Scanning",
      tone: "loading",
      detail: "Reviewing pipeline settings for release safety."
    },
    {
      title: "Integrity",
      value: "Scanning",
      tone: "loading",
      detail: "Refreshing manifest, SHA-256, and signature status."
    }
  ],
  danger: [
    {
      title: "SHA-256",
      value: "Failed",
      tone: "danger",
      detail: "The hash mismatch blocks the release decision."
    },
    {
      title: "Digital Signature",
      value: "Invalid",
      tone: "danger",
      detail: "Signature verification did not produce a valid trust signal."
    },
    {
      title: "Secret Scanning",
      value: "Critical Secret Found",
      tone: "danger",
      detail: "The exposure signal is strong. Revoke the key and clean the repository."
    },
    {
      title: "CI/CD",
      value: "High Risk",
      tone: "danger",
      detail: "Write permissions or unsafe commands make the release pipeline risky."
    },
    {
      title: "Dependencies",
      value: "Risky Package Found",
      tone: "danger",
      detail: "Known vulnerabilities directly affect the release decision."
    }
  ],
  caution: [
    {
      title: "Secret scanning",
      value: "Warning",
      tone: "caution",
      detail: "Suspicious values were found and should be verified."
    },
    {
      title: "Dependencies",
      value: "Warning",
      tone: "caution",
      detail: "Packages waiting for updates lower the security score."
    },
    {
      title: "CI/CD policy",
      value: "Limited Risk",
      tone: "caution",
      detail: "Workflow settings should be tightened before release."
    },
    {
      title: "Integrity",
      value: "Monitoring",
      tone: "caution",
      detail: "Cryptographic signals are available, but the decision has lower confidence."
    }
  ],
  controlled: [
    {
      title: "SHA-256",
      value: "Passed",
      tone: "safe",
      detail: "The hash check produced the expected trust signal."
    },
    {
      title: "Digital Signature",
      value: "Review",
      tone: "controlled",
      detail: "Verify the signature again before a final release decision."
    },
    {
      title: "Secret Scanning",
      value: "Monitor",
      tone: "attention",
      detail: "No critical exposure was found, but suspicious patterns should be reviewed."
    },
    {
      title: "CI/CD",
      value: "Review Carefully",
      tone: "attention",
      detail: "Workflow settings are acceptable but should still be reviewed before release."
    }
  ],
  safe: [
    {
      title: "Secret scanning",
      value: "Clean",
      tone: "safe",
      detail: "No secret pattern was found."
    },
    {
      title: "Dependencies",
      value: "Clean",
      tone: "safe",
      detail: "No known risky dependency is visible."
    },
    {
      title: "CI/CD policy",
      value: "Secure",
      tone: "safe",
      detail: "Workflow permissions look healthy for release."
    },
    {
      title: "Integrity",
      value: "Verified",
      tone: "safe",
      detail: "SHA-256, manifest, and digital signature match."
    }
  ]
};
