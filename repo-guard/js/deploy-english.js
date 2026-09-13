(() => {
  "use strict";

  // Match the layout density of viewing the original UI at 80% browser zoom.
  document.documentElement.lang = "en";
  document.documentElement.style.zoom = "0.8";
  document.body.style.width = "125%";
  document.body.style.minHeight = "125vh";
  document.body.style.overflowX = "hidden";

  const phrases = new Map([
    ["Repo Güvenlik Analizi", "Repository Security Analysis"],
    ["Repo'nu buraya yazalım mı?", "Want to scan your repo?"],
    ["GitHub URL, demo repo adı veya yerel klasör", "GitHub URL, demo repository name, or local folder"],
    ["GitHub repo URL'si girin", "Enter a GitHub repository URL"],
    ["Güvenlik Taramasını Başlat", "Start Security Scan"],
    ["Güvenlik Seviyesini Göster", "Show Security Level"],
    ["Örnekler: secure-demo-repo, review-demo-repo, cleanup-demo-repo, critical-demo-repo", "Examples: secure-demo-repo, review-demo-repo, cleanup-demo-repo, critical-demo-repo"],
    ["Örn: https://github.com/kullanici/repo", "Example: https://github.com/user/repo"],
    ["Güvenli demo", "Secure demo"],
    ["Kontrol demo", "Review demo"],
    ["Toparlanacak demo", "Cleanup demo"],
    ["Kritik demo", "Critical demo"],
    ["Canlı Atak Simülasyonu", "Live Attack Simulation"],
    ["Simülasyonu Aç", "Open Simulation"],
    ["Demo repoda güvenlik risklerini kontrollü olarak oluşturup skorun ve yayın durumunun nasıl değiştiğini ayrı ekranda gör.", "Create controlled security risks in the demo repository and see how the score and release status change."],
    ["Repo analiz ediliyor", "Analyzing repository"],
    ["Repo taranıyor", "Scanning repository"],
    ["Dosya parmak izi, imza ve güvenlik kontrolleri hazırlanıyor.", "Preparing file fingerprint, signature, and security checks."],
    ["Gizli bilgi, bağımlılık, otomasyon, dosya parmak izi, imza, manifest ve bütünlük kontrolleri çalışıyor.", "Running secret, dependency, CI/CD, fingerprint, signature, manifest, and integrity checks."],
    ["Endişelenme, her şey güvende!", "Your data stays protected."],
    ["Kişisel verilerin saklanmaz.", "Personal data is not stored."],
    ["Repo girdisi yalnızca yerel RepoGuard tarama servisine gönderilir.", "Repository input is processed by RepoGuard for the scan."],
    ["Bulgular ekrana gelmeden önce maskelenir.", "Sensitive findings are masked before they are displayed."],
    ["Bu repo gayet güvende!", "This repository looks secure!"],
    ["Dur! Önce kritik bulguları temizleyelim.", "Critical findings need attention first!"],
    ["Bazı noktaları toparlayalım, olur mu?", "A few issues need to be fixed."],
    ["Bir bakalım... bazı noktaları kontrol edelim!", "A few items need review."],
    ["Ayrıntılı Raporu Aç", "Open Detailed Report"],
    ["Özet hazır.", "Summary ready."],
    ["Bulunan sorunlar", "Findings"],
    ["Önerilen sonraki adımlar", "Recommended Next Steps"],
    ["Rapor notu", "Report Note"],
    ["Yayın doğrulaması ve repo bütünlüğü kontrolleri tamamlandı.", "Release verification and repository integrity checks are complete."],
    ["Hassas değerler ekranda gösterilmeden önce maskelenir.", "Sensitive values are masked before being displayed."],

    ["Kritik Risk", "Critical Risk"],
    ["Düzeltme Gerekli", "Fix Required"],
    ["İnceleme Gerekli", "Review Required"],
    ["Onaylandı", "Approved"],
    ["BLOKE", "BLOCKED"],
    ["DÜZELT", "FIX"],
    ["İNCELE", "REVIEW"],
    ["ONAY", "APPROVED"],
    ["Yayın süreci devam etmemeli", "Release must not continue"],
    ["Bazı kontroller iyileştirme istiyor", "Some checks require fixes"],
    ["Manuel kontrol önerilir", "Manual review recommended"],
    ["Tarama kontrolleri geçti", "Scan checks passed"],

    ["Gizli Bilgi", "Secrets"],
    ["Gizli bilgi", "Secrets"],
    ["Bağımlılıklar", "Dependencies"],
    ["Bağımlılık", "Dependency"],
    ["Otomasyon", "CI/CD"],
    ["Dijital İmza", "Digital Signature"],
    ["Repo Bütünlüğü", "Repository Integrity"],
    ["Yayın", "Release"],
    ["Temiz", "Clean"],
    ["Güvenli", "Secure"],
    ["Kontrol Et", "Review"],
    ["İzlenmeli", "Monitor"],
    ["Gözden Geçir", "Review"],
    ["Uyarı", "Warning"],
    ["Güncelle", "Update"],
    ["Sıkılaştır", "Harden"],
    ["İzlemede", "Monitoring"],
    ["Kritik", "Critical"],
    ["Riskli", "Risky"],
    ["Yüksek Risk", "High Risk"],
    ["Başarısız", "Failed"],
    ["Geçersiz", "Invalid"],
    ["Geçti", "Passed"],
    ["Doğrulandı", "Verified"],
    ["Beklemede", "Pending"],

    ["Güvenlik puanı", "Security Score"],
    ["Sonuç", "Result"],
    ["Açık sorun", "Open Findings"],
    ["Etkilenen dosya", "Affected Files"],
    ["Bekleniyor", "Waiting"],
    ["Teknik kontroller", "Technical Checks"],
    ["Tarama tamamlandıktan sonra teknik kanıtlar bu kapalı bölümde gösterilir.", "Technical evidence appears here after the scan is complete."],
    ["Maskelenmiş önizlemelerle gizli bilgi tespiti", "Secret detection with masked previews"],
    ["Bilinen riskli paket sürümleri", "Known vulnerable package versions"],
    ["İş akışı izinleri ve tedarik zinciri riskleri", "Workflow permissions and supply-chain risks"],
    ["Dosya parmak izi, manifest ve imza doğrulaması", "Fingerprint, manifest, and signature verification"],
    ["Repo bütünlük referansı denetimi", "Repository integrity baseline check"],
    ["Henüz rapor oluşturulmadı", "No report yet"],
    ["Ayrıntılı raporu görmek için önce bir repo taraması başlat. Tarama tamamlandığında burada sade özet, bulgular ve teknik kanıtlar görünecek.", "Start a repository scan to view the detailed report. Once complete, the summary, findings, and technical evidence will appear here."],
    ["Öne çıkan uyarı yok; çünkü henüz tarama sonucu alınmadı.", "There are no highlighted warnings because no scan has been run yet."],
    ["Tarama raporu yok", "No Scan Report"],
    ["Önce repo taraması çalıştır.", "Run a repository scan first."],
    ["Tarama tamamlandığında açık sorunlar burada anlaşılır kartlar halinde listelenecek.", "Open findings will be listed here as clear cards after the scan completes."],

    ["Referansı sıfırla", "Reset Baseline"],
    ["Sonucu görmek için bir simülasyon seç.", "Choose a simulation to see the result."],
    ["Atak simülasyonu çalıştırılıyor...", "Running attack simulation..."],
    ["Referans durum sıfırlanıyor...", "Resetting baseline..."],
    ["Simülasyon çalışmadı", "Simulation Failed"],
    ["Tarama servisine ulaşılamadı. Demo servisini başlatıp tekrar deneyebilirsin.", "The scan service could not be reached. Start the demo service and try again."],
    ["Simülasyon tamamlandı.", "Simulation complete."],
    ["Önce", "Before"],
    ["Sonra", "After"],
    ["Kayıt zinciri", "Audit Chain"],
    ["Geçerli", "Valid"],
    ["Bozuk", "Broken"],
    ["Referans tarama", "Baseline Scan"],
    ["Yayın dosyası değiştirildi", "Release Artifact Tampered"],
    ["Gizli bilgi eklendi", "Secret Added"],
    ["Riskli otomasyon eklendi", "Risky Workflow Added"],
    ["İmza bozuldu", "Signature Broken"],
    ["Politika kararı", "Policy Decision"],
    ["Yayın dosyasını değiştir", "Tamper Release Artifact"],
    ["Gizli bilgi ekle", "Add Secret"],
    ["Riskli otomasyon ekle", "Add Risky Workflow"],
    ["İmzayı boz", "Break Signature"],

    ["RepoGuard bu repoda yayını engelleyen bir sorun bulmadı. Yayın imzalamayı ve bağımlılık takibini sürdür.", "RepoGuard found no release-blocking issues in this repository. Keep release signing and dependency monitoring enabled."],
    ["Repo kullanılabilir bir temele sahip, ama imza ve otomasyon notları dikkatli incelenmeli.", "The repository has a usable baseline, but signature and CI/CD notes should be reviewed carefully."],
    ["Bu repo yayından önce toparlanmalı. Bağımlılık ve secret uyarılarını temizledikten sonra tekrar tara.", "This repository needs fixes before release. Resolve dependency and secret warnings, then scan again."],
    ["RepoGuard yayını engelleyen kritik risk buldu. Gizli bilgi, imza ve otomasyon bulgularını düzeltmeden yayın sürecini sürdürme.", "RepoGuard found critical release-blocking risks. Resolve secret, signature, and CI/CD findings before continuing the release."],
    ["RepoGuard yayını engelleyen risk buldu. En yüksek öncelikli bulguları düzelt, yayını yeniden oluştur ve tekrar tara.", "RepoGuard found release-blocking risk. Fix the highest-priority findings, rebuild the release, and scan again."],
    ["Bu repo yayından önce düzeltilmeli. Raporu incele, düzeltmelerden sonra taramayı yeniden çalıştır.", "This repository should be fixed before release. Review the report and run the scan again after the fixes."],
    ["Repo kullanılabilir bir temele sahip, ama güvenlik raporu dikkatli incelenmeli.", "The repository has a usable baseline, but the security report should be reviewed carefully."],
    ["RepoGuard taramasında yayını engelleyen bir sorun bulmadı. Yayın imzalamayı ve bağımlılık takibini sürdür.", "RepoGuard found no release-blocking issues. Keep release signing and dependency monitoring enabled."],
    ["Tüm tarama kontrolleri geçti: gizli bilgi, bağımlılık, otomasyon, dosya parmak izi, imza, manifest ve repo bütünlüğü.", "All scan checks passed: secrets, dependencies, CI/CD, fingerprint, signature, manifest, and repository integrity."],
    ["RepoGuard inceleme gerektiren bulgular buldu. Açıklama, kanıt ve aksiyonlar için ayrıntılı raporu aç.", "RepoGuard found items that require review. Open the detailed report for explanations, evidence, and actions."],

    ["Kod içindeki gizli bilgileri kaldır, sızmış olabilecek değerleri yenile ve güvenli bir gizli bilgi deposu kullan.", "Remove hardcoded secrets, rotate any potentially exposed values, and use a secure secret store."],
    ["Riskli paketleri önerilen güvenli sürümlere güncelle.", "Update risky packages to the recommended safe versions."],
    ["Otomasyon izinlerini daralt, kullanılan otomasyon bileşeni sürümlerini sabitle ve güvenilmeyen katkı isteği akışlarını izole et.", "Reduce CI/CD permissions, pin action versions, and isolate untrusted pull-request workflows."],
    ["Yayın dosyasını yeniden oluştur, manifesti yenile ve güvenilen anahtarla imzala.", "Rebuild the release artifact, regenerate the manifest, and sign it with a trusted key."],
    ["Yeni güvenilir repo referansını onaylamadan önce değişen dosyaları incele.", "Review changed files before approving a new trusted repository baseline."],
    ["Sonraki raporun kapsamı tam olsun diye tarama hatalarını çöz.", "Resolve scan errors so the next report has complete coverage."],
    ["Yayın imzalama, paket güncelleme ve dar otomasyon izni kontrollerini düzenli yayın listende tut.", "Keep release signing, package updates, and least-privilege CI/CD checks in your regular release checklist."],

    ["Kod içi gizli bilgi", "Hardcoded Secret"],
    ["Bilinen güvenlik açığı olan paket sürümü.", "Package version with a known vulnerability."],
    ["Otomasyon gereğinden geniş yazma yetkisiyle çalışıyor.", "The workflow runs with unnecessarily broad write permissions."],
    ["İzinleri job bazında en düşük yetkiye indir.", "Reduce permissions to least privilege for each job."],
    ["Kaynak kodda yüksek güvenliğe sahip token deseni bulundu.", "A high-confidence token pattern was found in source code."],
    ["Token değerini iptal et, geçmiş commitleri temizle ve secret manager kullan.", "Revoke the token, clean it from commit history, and use a secret manager."],
    ["Demo anahtar benzeri bir değer bulundu.", "A demo API-key-like value was found."],
    ["Değeri ortam değişkeni veya gizli bilgi yöneticisi üzerinden yükle.", "Load the value from an environment variable or secret manager."],
    ["Güvenilmeyen katkıların yayın hattında çalışması dikkat gerektirir.", "Running untrusted contributions in the release pipeline requires caution."],
    ["Otomasyon tetikleyicisini daralt ve yayın işlerini manuel onaya bağla.", "Restrict the workflow trigger and require manual approval for release jobs."],
    ["Yayın dosyası manifestteki güvenilir hash ve imza verisiyle eşleşmiyor.", "The release artifact does not match the trusted hash and signature data in the manifest."],
    ["Yayın dosyası manifest, SHA-256 ve dijital imza kontrollerinden geçti.", "The release artifact passed manifest, SHA-256, and digital-signature checks."],
    ["Repo bütünlük referansı beklenen kayıtla eşleşmiyor.", "The repository integrity baseline does not match the expected record."],
    ["Repo bütünlük referansı beklenen güvenilir kayıtla eşleşiyor.", "The repository integrity baseline matches the trusted record."],
  ]);

  // Fallback replacements catch short dynamically generated labels that are not exact phrase matches.
  const fallback = [
    [/\bGüvenlik\b/gi, "Security"],
    [/\bTarama\b/gi, "Scan"],
    [/\bRapor\b/gi, "Report"],
    [/\bBulgular\b/gi, "Findings"],
    [/\bBulgu\b/gi, "Finding"],
    [/\bDosya\b/gi, "File"],
    [/\bİmza\b/gi, "Signature"],
    [/\bManifest\b/gi, "Manifest"],
    [/\bBütünlük\b/gi, "Integrity"],
    [/\bYayın\b/gi, "Release"],
    [/\bBağımlılıklar\b/gi, "Dependencies"],
    [/\bBağımlılık\b/gi, "Dependency"],
    [/\bOtomasyon\b/gi, "CI/CD"],
    [/\bTemiz\b/gi, "Clean"],
    [/\bKritik\b/gi, "Critical"],
    [/\bUyarı\b/gi, "Warning"],
    [/\bÖnerilen\b/gi, "Recommended"],
    [/\bAksiyonlar\b/gi, "Actions"],
    [/\bAçık\b/gi, "Open"],
    [/\bSorun\b/gi, "Issue"],
  ];

  const sortedPhrases = [...phrases.entries()].sort((a, b) => b[0].length - a[0].length);

  function translateString(input) {
    if (!input || typeof input !== "string") return input;
    let output = input;
    for (const [tr, en] of sortedPhrases) {
      if (output.includes(tr)) output = output.split(tr).join(en);
    }
    for (const [pattern, replacement] of fallback) {
      output = output.replace(pattern, replacement);
    }
    return output;
  }

  function translateElementAttributes(element) {
    for (const attribute of ["placeholder", "title", "aria-label", "alt"]) {
      if (!element.hasAttribute?.(attribute)) continue;
      const current = element.getAttribute(attribute);
      const translated = translateString(current);
      if (translated !== current) element.setAttribute(attribute, translated);
    }
  }

  function translateTree(root) {
    if (!root) return;
    if (root.nodeType === Node.TEXT_NODE) {
      const translated = translateString(root.nodeValue);
      if (translated !== root.nodeValue) root.nodeValue = translated;
      return;
    }
    if (root.nodeType !== Node.ELEMENT_NODE && root.nodeType !== Node.DOCUMENT_NODE) return;

    if (root.nodeType === Node.ELEMENT_NODE) translateElementAttributes(root);
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT);
    let node;
    while ((node = walker.nextNode())) {
      if (node.nodeType === Node.TEXT_NODE) {
        const translated = translateString(node.nodeValue);
        if (translated !== node.nodeValue) node.nodeValue = translated;
      } else {
        translateElementAttributes(node);
      }
    }
  }

  translateTree(document.body);
  document.title = "RepoGuard | Repository Security Analysis";

  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      if (mutation.type === "characterData") {
        translateTree(mutation.target);
      } else {
        for (const node of mutation.addedNodes) translateTree(node);
      }
    }
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true,
    characterData: true,
  });
})();
