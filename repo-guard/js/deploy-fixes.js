(() => {
  "use strict";

  // Keep the AWS-hosted demo at the requested 90% visual scale.
  document.documentElement.lang = "en";
  document.documentElement.style.zoom = "0.9";
  document.body.style.width = "111.111111%";
  document.body.style.minHeight = "111.111111vh";
  document.body.style.overflowX = "hidden";

  const attributeTranslations = new Map([
    ["GitHub URL, demo repo adı veya yerel klasör", "GitHub URL, demo repository name, or local folder"],
    ["GitHub repo URL'si girin", "Enter a GitHub repository URL"],
    ["RepoGuard arama ekranı", "RepoGuard search screen"],
    ["RepoGuard analiz sonucu", "RepoGuard scan result"],
    ["Güvenlik notu", "Security note"],
    ["Önerilen aksiyonlar", "Recommended actions"],
    ["Kalkan tutan mutlu RepoGuard tavşan maskotu", "Happy RepoGuard bunny mascot holding a shield"],
    ["RepoGuard arama alanını gösteren sevimli tavşan maskotu", "RepoGuard bunny mascot pointing to the repository field"],
  ]);

  const textTranslations = new Map([
    ["Repo'nu buraya yazalım mı?", "Want to scan your repo?"],
    ["Repo Güvenlik Analizi", "Repository Security Analysis"],
    ["Güvenlik Taramasını Başlat", "Start Security Scan"],
    ["Güvenlik Seviyesini Göster", "Show Security Level"],
    ["Örnekler:", "Examples:"],
    ["Güvenli demo", "Secure demo"],
    ["Kontrol demo", "Review demo"],
    ["Toparlanacak demo", "Cleanup demo"],
    ["Kritik demo", "Critical demo"],
    ["Canlı Atak Simülasyonu", "Live Attack Simulation"],
    ["Simülasyonu Aç", "Open Simulation"],
    ["Ayrıntılı Raporu Aç", "Open Detailed Report"],
    ["Bulunan sorunlar", "Findings"],
    ["Önerilen sonraki adımlar", "Recommended Next Steps"],
  ]);

  function translateValue(value, map) {
    if (!value) return value;
    let output = String(value);
    for (const [source, target] of map) {
      if (output.includes(source)) output = output.replaceAll(source, target);
    }
    return output;
  }

  function translateAttributes(element) {
    if (!(element instanceof Element)) return;
    for (const name of ["placeholder", "title", "aria-label", "alt"]) {
      if (!element.hasAttribute(name)) continue;
      const current = element.getAttribute(name);
      const translated = translateValue(current, attributeTranslations);
      if (translated !== current) element.setAttribute(name, translated);
    }
  }

  function translateNode(node) {
    if (!node) return;
    if (node.nodeType === Node.TEXT_NODE) {
      const translated = translateValue(node.nodeValue, textTranslations);
      if (translated !== node.nodeValue) node.nodeValue = translated;
      return;
    }
    if (!(node instanceof Element)) return;
    translateAttributes(node);
    node.childNodes.forEach(translateNode);
  }

  function enforceEnglishInput() {
    const input = document.querySelector("#repoUrl");
    if (input) {
      input.setAttribute("placeholder", "GitHub URL, demo repository name, or local folder");
      input.setAttribute("aria-label", "GitHub repository URL or demo repository name");
    }
  }

  translateNode(document.body);
  enforceEnglishInput();

  // app.js updates some text/attributes after initial parsing. Watch both DOM and attributes.
  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      if (mutation.type === "attributes") {
        translateAttributes(mutation.target);
      } else if (mutation.type === "characterData") {
        translateNode(mutation.target);
      } else {
        mutation.addedNodes.forEach(translateNode);
      }
    }
    enforceEnglishInput();
  });

  observer.observe(document.documentElement, {
    subtree: true,
    childList: true,
    characterData: true,
    attributes: true,
    attributeFilter: ["placeholder", "title", "aria-label", "alt"],
  });

  // One final pass after deferred app initialization.
  window.addEventListener("DOMContentLoaded", () => {
    translateNode(document.body);
    enforceEnglishInput();
  });
})();
