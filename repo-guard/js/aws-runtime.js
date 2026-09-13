(() => {
  "use strict";

  document.documentElement.lang = "en";

  const style = document.createElement("style");
  style.textContent = `
    @media (min-width: 900px) {
      body {
        zoom: 0.9;
        width: 111.111111%;
        margin: 0;
        overflow-x: hidden;
      }
      #appShell {
        margin-left: auto !important;
        margin-right: auto !important;
      }
    }
    .aws-demo-note {
      margin: 12px auto 0;
      max-width: 760px;
      padding: 10px 14px;
      border: 1px solid rgba(139,116,184,.25);
      border-radius: 14px;
      background: rgba(255,255,255,.72);
      color: #6f5b8e;
      font: 700 13px/1.4 Nunito, sans-serif;
      text-align: center;
    }
  `;
  document.head.append(style);

  const exact = new Map([
    ["Repo Güvenlik Analizi", "Repository Security Analysis"],
    ["RepoGuard arama ekranı", "RepoGuard search screen"],
    ["RepoGuard arama alanını gösteren sevimli tavşan maskotu", "RepoGuard bunny mascot pointing to the repository input"],
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
    ["Tarama kısayolları", "Scan shortcuts"],

    ["Canlı Atak Simülasyonu", "Live Attack Simulation"],
    ["RepoGuard canlı atak simülasyonu", "RepoGuard live attack simulation"],
    ["Simülasyonu Aç", "Open Simulation"],
    ["Demo repoda güvenlik risklerini kontrollü olarak oluşturup skorun ve yayın durumunun nasıl değiştiğini ayrı ekranda gör.", "Create controlled security risks in the demo repository and see how the score and release status change."],
    ["Ana ekrana dön", "Back to Home"],
    ["Kontrollü güvenlik testi yapan RepoGuard tavşan maskotu", "RepoGuard bunny mascot running a controlled security test"],
    ["Opsiyonel demo aracı", "Optional demo tool"],
    ["Bu ekran, rapordan ayrı çalışır. Demo repoda kontrollü risk senaryoları üretir ve RepoGuard kararının nasıl değiştiğini gösterir.", "This screen runs separately from the report. It creates controlled risk scenarios in the demo repository and shows how the RepoGuard decision changes."],
    ["Simülasyon seçenekleri", "Simulation options"],
    ["Bir senaryo seç", "Choose a scenario"],
    ["Simülasyon yalnızca demo ortamı içindir; gerçek repolarda değişiklik yapmadan önce tarama sonucunu ayrıca kontrol et.", "The simulation is for the demo environment only. Review scan results separately before making changes to a real repository."],
    ["Referansı sıfırla", "Reset Baseline"],
    ["Yayın dosyasını değiştir", "Tamper Release Artifact"],
    ["Gizli bilgi ekle", "Add Secret"],
    ["Riskli otomasyon ekle", "Add Risky Workflow"],
    ["İmzayı boz", "Break Signature"],
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
    ["Bu yanıtta kayıt zinciri olayı bulunmadı.", "No audit-chain events were returned."],

    ["Repo analiz ediliyor", "Analyzing repository"],
    ["Repo taranıyor", "Scanning repository"],
    ["Dosya parmak izi, imza ve güvenlik kontrolleri hazırlanıyor.", "Preparing file fingerprint, signature, and security checks."],
    ["Gizli bilgi, bağımlılık, otomasyon, dosya parmak izi, imza, manifest ve bütünlük kontrolleri çalışıyor.", "Running secret, dependency, CI/CD, fingerprint, signature, manifest, and integrity checks."],
    ["Güvenlik notu", "Security note"],
    ["Endişelenme, her şey güvende!", "Your data stays protected."],
    ["Kişisel verilerin saklanmaz.", "Personal data is not stored."],
    ["Repo girdisi yalnızca yerel RepoGuard tarama servisine gönderilir.", "Repository input is processed by RepoGuard for the scan."],
    ["Bulgular ekrana gelmeden önce maskelenir.", "Sensitive findings are masked before display."],

    ["Kalkan tutan mutlu RepoGuard tavşan maskotu", "Happy RepoGuard bunny mascot holding a shield"],
    ["RepoGuard analiz sonucu", "RepoGuard analysis result"],
    ["Güvenlik puanı", "Security Score"],
    ["Güvenlik Skoru", "Security Score"],
    ["Güvenli", "Secure"],
    ["Yüksek Güvenlik Seviyesi", "High Security Level"],
    ["Analiz edilen repository", "Analyzed repository"],
    ["Kontrol sonuçları", "Check results"],
    ["Dijital İmza", "Digital Signature"],
    ["Gizli Bilgi", "Secrets"],
    ["Otomasyon", "CI/CD"],
    ["Düşük Risk", "Low Risk"],
    ["Sonuç önerisi", "Result recommendation"],
    ["Güzel iş! Bu repo güvenli görünüyor.", "Nice! This repository looks secure."],
    ["Yoluna güvenle devam edebilirsin!", "You can continue with confidence!"],
    ["Ayrıntılı Rapor Göster", "Show Detailed Report"],
    ["Ayrıntılı Raporu Aç", "Open Detailed Report"],
    ["Bu repo gayet güvende!", "This repository looks secure!"],
    ["Dur! Önce kritik bulguları temizleyelim.", "Critical findings need attention first!"],
    ["Bazı noktaları toparlayalım, olur mu?", "A few issues need to be fixed."],
    ["Bir bakalım... bazı noktaları kontrol edelim!", "A few items need review."],

    ["Kritik Risk", "Critical Risk"],
    ["Düzeltme Gerekli", "Fix Required"],
    ["İnceleme Gerekli", "Review Required"],
    ["Onaylandı", "Approved"],
    ["Bloke", "Blocked"],
    ["BLOKE", "BLOCKED"],
    ["DÜZELT", "FIX"],
    ["İNCELE", "REVIEW"],
    ["ONAY", "APPROVED"],
    ["Yayın süreci devam etmemeli", "Release must not continue"],
    ["Bazı kontroller iyileştirme istiyor", "Some checks require fixes"],
    ["Manuel kontrol önerilir", "Manual review recommended"],
    ["Tarama kontrolleri geçti", "Scan checks passed"],
    ["Taranıyor", "Scanning"],
    ["Önce repo kaynağını yazalım.", "Enter a repository source first."],
    ["Repo kaynağı gerekli.", "A repository source is required."],
    ["Tarama servisi bu işlemi tamamlayamadı.", "The scan service could not complete this request."],
    ["Tarama başarısız oldu. Servisi kontrol edip tekrar dene.", "The scan failed. Check the service and try again."],
    ["Tarama zaman aşımına uğradı. Daha küçük bir repo dene veya tarama servisi kayıtlarını kontrol et.", "The scan timed out. Try a smaller repository or check the scan-service logs."],
    ["Tarama servisine erişilemiyor. Şu komutla başlat: python dashboard.py --serve", "The scan service is unavailable. Start it with: python dashboard.py --serve"],

    ["RepoGuard bu repoda yayını engelleyen bir sorun bulmadı. Yayın imzalamayı ve bağımlılık takibini sürdür.", "RepoGuard found no release-blocking issues in this repository. Keep release signing and dependency monitoring enabled."],
    ["Repo kullanılabilir bir temele sahip, ama imza ve otomasyon notları dikkatli incelenmeli.", "The repository has a usable baseline, but signature and CI/CD notes should be reviewed carefully."],
    ["Bu repo yayından önce toparlanmalı. Bağımlılık ve secret uyarılarını temizledikten sonra tekrar tara.", "This repository needs fixes before release. Resolve dependency and secret warnings, then scan again."],
    ["RepoGuard yayını engelleyen kritik risk buldu. Gizli bilgi, imza ve otomasyon bulgularını düzeltmeden yayın sürecini sürdürme.", "RepoGuard found critical release-blocking risks. Resolve secret, signature, and CI/CD findings before continuing the release."],
    ["RepoGuard yayını engelleyen risk buldu. En yüksek öncelikli bulguları düzelt, yayını yeniden oluştur ve tekrar tara.", "RepoGuard found release-blocking risk. Fix the highest-priority findings, rebuild the release, and scan again."],
    ["Bu repo yayından önce düzeltilmeli. Raporu incele, düzeltmelerden sonra taramayı yeniden çalıştır.", "This repository should be fixed before release. Review the report and run the scan again after the fixes."],
    ["Repo kullanılabilir bir temele sahip, ama güvenlik raporu dikkatli incelenmeli.", "The repository has a usable baseline, but the security report should be reviewed carefully."],
    ["RepoGuard taramasında yayını engelleyen bir sorun bulmadı. Yayın imzalamayı ve bağımlılık takibini sürdür.", "RepoGuard found no release-blocking issues. Keep release signing and dependency monitoring enabled."],
    ["Tüm tarama kontrolleri geçti: gizli bilgi, bağımlılık, otomasyon, dosya parmak izi, imza, manifest ve repo bütünlüğü.", "All scan checks passed: secrets, dependencies, CI/CD, fingerprint, signature, manifest, and repository integrity."],
    ["Tarama temiz: gizli bilgi, bağımlılık ve otomasyon bulgusu yok. Yayın kanıtı bulunmadığı için yayın doğrulaması uygulanamaz.", "The scan is clean: no secret, dependency, or CI/CD findings. Release verification is not applicable because no release evidence was found."],
    ["RepoGuard inceleme gerektiren bulgular buldu. Açıklama, kanıt ve aksiyonlar için ayrıntılı raporu aç.", "RepoGuard found items that require review. Open the detailed report for explanations, evidence, and actions."],

    ["RepoGuard ayrıntılı güvenlik raporu", "RepoGuard detailed security report"],
    ["Ayrıntılı Güvenlik Raporu", "Detailed Security Report"],
    ["Rapor özeti", "Report summary"],
    ["Skor", "Score"],
    ["Durum", "Status"],
    ["Dikkat", "Attention"],
    ["Açık Bulgu", "Open Findings"],
    ["Etkilenen Dosya", "Affected Files"],
    ["Bulunan sorunlar", "Findings"],
    ["Bulgu listesi", "Findings list"],
    ["Kod içi gizli bilgi", "Hardcoded Secret"],
    ["Gizli değer maskelendi", "Secret value masked"],
    ["Yüksek", "High"],
    ["Orta", "Medium"],
    ["Düşük", "Low"],
    ["Kritik", "Critical"],
    ["SHA-256 uyuşmazlığı", "SHA-256 mismatch"],
    ["Dosya bütünlüğü bozulmuş", "File integrity changed"],
    ["Riskli bağımlılık tespit edildi", "Risky dependency detected"],
    ["Rapor notu", "Report Note"],
    ["Yayın doğrulaması ve repo bütünlüğü kontrolleri tamamlandı.", "Release verification and repository integrity checks are complete."],
    ["Hassas değerler ekranda gösterilmeden önce maskelenir.", "Sensitive values are masked before display."],
    ["Önerilen aksiyonlar", "Recommended actions"],
    ["Önerilen sonraki adımlar", "Recommended Next Steps"],
    ["Gizli bilgileri kaldır veya ortam değişkeni kullan", "Remove secrets or use environment variables"],
    ["Otomasyon izinlerini daralt", "Reduce CI/CD permissions"],
    ["Yayın dosyasını yeniden imzala ve dosya parmak izini doğrula", "Re-sign the release artifact and verify its fingerprint"],
    ["Bağımlılıkları güncelle", "Update dependencies"],
    ["Sorunları tek tek inceledim!", "I reviewed the findings one by one!"],
    ["Gozluk takan, buyutec ve pano tutan RepoGuard tavsan guvenlik mufettisi", "RepoGuard bunny security inspector with glasses, a magnifier, and a clipboard"],

    ["Genel durum", "Overview"],
    ["Repo güvenli görünüyor", "Repository looks secure"],
    ["Tarama, yayını durduracak açık bir sorun bulmadı. Yine de paket güncellemelerini ve yayın imzasını düzenli kontrol etmeye devam et.", "The scan found no issue that should block release. Continue checking package updates and release signatures regularly."],
    ["Repo yayın öncesi gözden geçirilmeli", "Repository should be reviewed before release"],
    ["Genel tablo yönetilebilir görünüyor, ancak bazı noktalar insan kontrolü istiyor. Bulguları sırayla inceleyip tekrar tarama yapman iyi olur.", "The overall state looks manageable, but some items require human review. Check the findings and scan again afterward."],
    ["Repo yayından önce düzeltilmeli", "Repository needs fixes before release"],
    ["Tarama, kötüye kullanılabilecek riskler buldu. Önce yüksek riskli sorunları kapat, ardından taramayı yeniden çalıştır.", "The scan found risks that could be exploited. Fix high-risk issues first, then run the scan again."],
    ["Yayın için güvenli değil", "Not safe for release"],
    ["RepoGuard yayını durdurabilecek kritik riskler buldu. Bu repoyu düzeltmeler tamamlanmadan canlı ortama taşımamalısın.", "RepoGuard found critical risks that can block release. Do not move this repository to production until the fixes are complete."],
    ["Öne çıkan uyarı yok. Rapor temiz görünüyor.", "No top warning. The report looks clean."],
    ["Puan", "Score"],
    ["Yayınlanabilir", "Ready to Release"],
    ["Yayınlama", "Do Not Release"],
    ["İncele", "Review"],
    ["Bilinmiyor", "Unknown"],
    ["Güvenlik puanı", "Security Score"],
    ["Sonuç", "Result"],
    ["Açık sorun", "Open Findings"],
    ["Etkilenen dosya", "Affected Files"],

    ["Temiz rapor", "Clean Report"],
    ["Açık sorun yok", "No Open Issues"],
    ["Gizli bilgi, bağımlılık, otomasyon, yayın imzası ve repo bütünlüğü kontrolleri geçti.", "Secret, dependency, CI/CD, release-signature, and repository-integrity checks passed."],
    ["Bu raporda hemen aksiyon gerektiren bir güvenlik bulgusu görünmüyor.", "No security finding in this report requires immediate action."],
    ["Bilgi", "Info"],
    ["Bulgu", "Finding"],
    ["Neden önemli?", "Why it matters"],
    ["Önerilen adım", "Recommended action"],
    ["Teknik detayları göster", "Show technical details"],
    ["Bulgu türü", "Finding type"],
    ["Konum", "Location"],
    ["Tarama notu", "Scan note"],
    ["Maskeli/teknik değer", "Masked/technical value"],
    ["Risk seviyesi", "Risk level"],

    ["Gizli bilgi", "Secrets"],
    ["Bağımlılık", "Dependency"],
    ["Bağımlılıklar", "Dependencies"],
    ["Yayın dosyası", "Release artifact"],
    ["İmza", "Signature"],
    ["Manifest", "Manifest"],
    ["Repo Bütünlüğü", "Repository Integrity"],
    ["Tarayıcı Hatası", "Scanner Error"],
    ["Uyarı", "Warning"],
    ["Gizli anahtar kod içinde bulundu", "A secret was found in source code"],
    ["Kodun içinde parola, token veya API anahtarı gibi saklanması gereken bir değer görünüyor.", "A value that should be protected, such as a password, token, or API key, appears in source code."],
    ["Bu değer gerçekse, repo erişimi olan biri sistemlere veya servis hesaplarına izinsiz erişebilir.", "If this value is real, someone with repository access could gain unauthorized access to systems or service accounts."],
    ["Gizli bilgi türü", "Secret type"],
    ["Entropi skoru", "Entropy score"],
    ["Tarama açıklaması", "Scan explanation"],
    ["Projede bilinen güvenlik riski taşıyan eski bir paket sürümü kullanılıyor.", "The project uses an outdated package version with a known security risk."],
    ["Eski paketler saldırganların hazır güvenlik açıklarını kullanmasına yol açabilir.", "Outdated packages can expose the project to known vulnerabilities."],
    ["Paket sistemi", "Package ecosystem"],
    ["Paket adı", "Package name"],
    ["Mevcut sürüm", "Current version"],
    ["Önerilen sürüm", "Recommended version"],
    ["Repo otomasyonunda gereğinden geniş izin veya dikkat isteyen bir çalışma ayarı bulundu.", "The repository workflow contains an overly broad permission or another setting that requires review."],
    ["Otomasyon dosyası", "Workflow file"],
    ["Tespit edilen ayar", "Detected setting"],
    ["Teknik açıklama", "Technical explanation"],
    ["Yayın dosyası beklenen dosyayla eşleşmiyor", "Release artifact does not match the expected artifact"],
    ["Yayınlanan dosyanın parmak izi, güvenilir kayıtla aynı değil.", "The release artifact fingerprint does not match the trusted record."],
    ["Bu durum dosyanın değişmiş, bozulmuş veya yanlış dosyanın yayınlanmış olabileceğini gösterir.", "This may indicate that the artifact was changed, corrupted, or the wrong file was released."],
    ["Yayın dosyasını yeniden oluştur, manifesti yenile ve düzeltilmiş manifesti imzala.", "Rebuild the release artifact, regenerate the manifest, and sign the corrected manifest."],
    ["Mevcut SHA-256", "Current SHA-256"],
    ["Beklenen SHA-256", "Expected SHA-256"],
    ["Tarama mesajı", "Scan message"],
    ["Yayın imzası doğrulanamadı", "Release signature could not be verified"],
    ["Yayın dosyasının güvenilir kişi veya süreç tarafından imzalandığı kanıtlanamıyor.", "The release artifact cannot be proven to have been signed by a trusted person or process."],
    ["İmza geçersizse kullanıcılar doğru dosyayı aldığından emin olamaz.", "If the signature is invalid, users cannot be sure they received the correct artifact."],
    ["İmzalama anahtarını doğrula, imzayı yeniden üret ve özel anahtarları repo dışında tut.", "Verify the signing key, generate the signature again, and keep private keys outside the repository."],
    ["İmza durumu", "Signature status"],
    ["Algoritma", "Algorithm"],
    ["İmza dosyası", "Signature file"],
    ["Manifest imzası güven vermiyor", "Manifest signature is not trusted"],
    ["Yayın listesini anlatan manifest dosyasının imzası doğrulanamadı.", "The signature of the release manifest could not be verified."],
    ["Manifest güvenilir değilse hangi dosyanın doğru yayın dosyası olduğu netleşmez.", "If the manifest is not trusted, it is unclear which artifact is the correct release."],
    ["Manifesti mevcut yayın dosyasından yeniden oluştur ve manifest hash değerini imzala.", "Regenerate the manifest from the current release artifact and sign the manifest hash."],
    ["Manifest SHA-256", "Manifest SHA-256"],
    ["Manifest imzası", "Manifest signature"],
    ["Doğrulama sonucu", "Verification result"],
    ["Repo beklenen güvenilir hâliyle eşleşmiyor", "Repository does not match the trusted baseline"],
    ["Repo içeriği, daha önce güvenilir kabul edilen referansla aynı görünmüyor.", "Repository contents do not match the previously trusted baseline."],
    ["Beklenmeyen dosya değişiklikleri yayın dosyası veya kritik ayarların değiştirilmiş olabileceğini gösterebilir.", "Unexpected file changes may indicate that release artifacts or critical settings were modified."],
    ["Değişen referans dosyalarını incele ve yeni güvenilir referansı yalnızca kod incelemesinden sonra onayla.", "Review changed baseline files and approve a new trusted baseline only after code review."],
    ["Mevcut kök", "Current root"],
    ["Beklenen kök", "Expected root"],
    ["Değişen dosyalar", "Changed files"],
    ["Yok", "None"],
    ["Tarama aracı bir kontrolü tamamlayamadı", "The scanner could not complete one check"],
    ["Tarama entegrasyon hatasıyla tamamlandı", "The scan completed with an integration error"],
    ["Raporun bir bölümü teknik hata nedeniyle eksik olabilir.", "Part of the report may be incomplete because of a technical error."],
    ["Eksik tarama sonucu, bazı risklerin henüz görülmemiş olabileceği anlamına gelir.", "An incomplete scan means some risks may not have been detected yet."],
    ["Tarama loglarını kontrol et ve hatayı düzelttikten sonra taramayı yeniden çalıştır.", "Check the scan logs, fix the error, and run the scan again."],
    ["Hata mesajı", "Error message"],
    ["Tarama uyarısı", "Scan warning"],
    ["Engelleyici olmayan tarama uyarısı", "Non-blocking scan warning"],
    ["Tarama tamamlandı, ancak dikkat edilmesi gereken bir not üretti.", "The scan completed but produced a note that should be reviewed."],
    ["Bu uyarı tek başına yayını durdurmayabilir; yine de kapsamın doğru olduğundan emin olmak gerekir.", "This warning may not block release by itself, but scan coverage should still be verified."],
    ["Uyarıyı incele ve tarama kapsamının yeterli olduğunu doğrula.", "Review the warning and confirm that scan coverage is sufficient."],
    ["Uyarı mesajı", "Warning message"],

    ["Teknik kanıtlar", "Technical evidence"],
    ["Teknik yayın kanıtları", "Technical Release Evidence"],
    ["Yayın doğrulaması tamamlandı.", "Release verification complete."],
    ["Dosya parmak izi eşleşmesi", "Artifact fingerprint match"],
    ["İmzalanan veri", "Signed payload"],
    ["Kayıtlı SHA-256", "Stored SHA-256"],
    ["Teknik repo bütünlüğü", "Technical Repository Integrity"],
    ["Repo bütünlüğü kontrolü tamamlandı.", "Repository integrity check complete."],
    ["Bütünlük durumu", "Integrity status"],
    ["Puanın teknik hesaplaması", "Technical Score Calculation"],
    ["Merak eden kullanıcılar için puanın nasıl düştüğünü gösterir.", "Shows how the score is reduced for users who want the technical details."],
    ["Sıkı modda puan düşüren kayıt yok.", "No strict-mode penalties were recorded."],
    ["Mod", "Mode"],
    ["ekran modu", "dashboard mode"],
    ["Kaynak cezası", "Source penalty"],
    ["Kripto cezası", "Crypto penalty"],
    ["Toplam ceza", "Total penalty"],
    ["Sıkı mod skoru", "Strict-mode score"],
    ["Yayın doğrulaması", "Release verification"],
    ["Repo bütünlüğü", "Repository integrity"],
    ["Alan", "Area"],
    ["Repo bütünlüğü değerlendirildi.", "Repository integrity was evaluated."],

    ["Henüz rapor oluşturulmadı", "No report yet"],
    ["Ayrıntılı raporu görmek için önce bir repo taraması başlat. Tarama tamamlandığında burada sade özet, bulgular ve teknik kanıtlar görünecek.", "Start a repository scan to view the detailed report. Once complete, the summary, findings, and technical evidence will appear here."],
    ["Öne çıkan uyarı yok; çünkü henüz tarama sonucu alınmadı.", "There are no highlighted warnings because no scan has been run yet."],
    ["Taranmadı", "Not Scanned"],
    ["Bekleniyor", "Waiting"],
    ["Tarama raporu yok", "No Scan Report"],
    ["Önce repo taraması çalıştır.", "Run a repository scan first."],
    ["Tarama tamamlandığında açık sorunlar burada anlaşılır kartlar halinde listelenecek.", "Open findings will be listed here as clear cards after the scan completes."],
    ["Teknik kontroller", "Technical Checks"],
    ["Tarama tamamlandıktan sonra teknik kanıtlar bu kapalı bölümde gösterilir.", "Technical evidence appears here after the scan is complete."],
    ["Maskelenmiş önizlemelerle gizli bilgi tespiti", "Secret detection with masked previews"],
    ["Bilinen riskli paket sürümleri", "Known vulnerable package versions"],
    ["İş akışı izinleri ve tedarik zinciri riskleri", "Workflow permissions and supply-chain risks"],
    ["Dosya parmak izi, manifest ve imza doğrulaması", "Fingerprint, manifest, and signature verification"],
    ["Bütünlük", "Integrity"],
    ["Repo bütünlük referansı denetimi", "Repository integrity baseline check"],

    ["Geçti", "Passed"],
    ["Başarısız", "Failed"],
    ["Hata", "Error"],
    ["Eksik", "Missing"],
    ["Uygulanamaz", "Not Applicable"],
    ["Yayın yok", "No Release"],
    ["Parmak izi uyuşmazlığı", "Fingerprint mismatch"],
    ["İmza geçersiz", "Signature invalid"],
    ["Hazır", "Ready"],
    ["Analiz ediliyor", "Analyzing"],
    ["Kontrollü", "Review"],
    ["Temiz", "Clean"],
    ["Kontrol Et", "Review"],
    ["İzlenmeli", "Monitor"],
    ["Gözden Geçir", "Review"],
    ["Güncelle", "Update"],
    ["Sıkılaştır", "Harden"],
    ["İzlemede", "Monitoring"],
    ["Riskli", "Risky"],
    ["Yüksek Risk", "High Risk"],
    ["Geçersiz", "Invalid"],
    ["Doğrulandı", "Verified"],
    ["Beklemede", "Pending"],

    ["Demo anahtar benzeri bir değer bulundu.", "A demo API-key-like value was found."],
    ["Değeri ortam değişkeni veya gizli bilgi yöneticisi üzerinden yükle.", "Load the value from an environment variable or secret manager."],
    ["Bilinen güvenlik açığı olan paket sürümü.", "Package version with a known vulnerability."],
    ["Güvenilmeyen katkıların yayın hattında çalışması dikkat gerektirir.", "Running untrusted pull-request code in the release pipeline requires extra care."],
    ["Otomasyon tetikleyicisini daralt ve yayın işlerini manuel onaya bağla.", "Narrow the workflow trigger and require manual approval for release jobs."],
    ["Kaynak kodda yüksek güvenliğe sahip token deseni bulundu.", "A high-confidence token pattern was found in source code."],
    ["Token değerini iptal et, geçmiş commitleri temizle ve secret manager kullan.", "Revoke the token, clean it from commit history, and use a secret manager."],
    ["Bilinen açık içeren eski paket sürümü.", "Outdated package version with a known vulnerability."],
    ["Otomasyon gereğinden geniş yazma yetkisiyle çalışıyor.", "The workflow runs with unnecessarily broad write permissions."],
    ["İzinleri job bazında en düşük yetkiye indir.", "Reduce permissions to least privilege for each job."],
    ["Yayın dosyası manifestteki güvenilir hash ve imza verisiyle eşleşmiyor.", "The release artifact does not match the trusted hash and signature data in the manifest."],
    ["Yayın dosyası manifest, SHA-256 ve dijital imza kontrollerinden geçti.", "The release artifact passed manifest, SHA-256, and digital-signature checks."],
    ["Repo bütünlük referansı beklenen kayıtla eşleşmiyor.", "The repository integrity baseline does not match the expected record."],
    ["Repo bütünlük referansı beklenen güvenilir kayıtla eşleşiyor.", "The repository integrity baseline matches the expected trusted record."],

    ["Kod içindeki gizli bilgileri kaldır, sızmış olabilecek değerleri yenile ve güvenli bir gizli bilgi deposu kullan.", "Remove hardcoded secrets, rotate any potentially exposed values, and use a secure secret store."],
    ["Riskli paketleri önerilen güvenli sürümlere güncelle.", "Update risky packages to the recommended safe versions."],
    ["Otomasyon izinlerini daralt, kullanılan otomasyon bileşeni sürümlerini sabitle ve güvenilmeyen katkı isteği akışlarını izole et.", "Reduce CI/CD permissions, pin action versions, and isolate untrusted pull-request workflows."],
    ["Yayın dosyasını yeniden oluştur, manifesti yenile ve güvenilen anahtarla imzala.", "Rebuild the release artifact, regenerate the manifest, and sign it with a trusted key."],
    ["Yeni güvenilir repo referansını onaylamadan önce değişen dosyaları incele.", "Review changed files before approving a new trusted repository baseline."],
    ["Sonraki raporun kapsamı tam olsun diye tarama hatalarını çöz.", "Resolve scan errors so the next report has complete coverage."],
    ["Yayın imzalama, paket güncelleme ve dar otomasyon izni kontrollerini düzenli yayın listende tut.", "Keep release signing, package updates, and least-privilege CI/CD checks in your regular release checklist."]
  ]);

  const partials = [
    ["Öne çıkan uyarı: ", "Top warning: "],
    ["Konum: ", "Location: "],
    ["Satır ", "Line "],
    [" / tür ", " / type "],
    ["Mevcut sürüm ", "Current version "],
    [" / önerilen sürüm ", " / recommended version "],
    ["Mevcut ", "Current "],
    [" / beklenen ", " / expected "],
    [" paket güncellenmeli", " package(s) should be updated"],
    [" için yazma erişimi veriyor; bu da workflow ele geçirildiğinde oluşabilecek etkiyi artırır.", " write access, increasing the impact of a compromised workflow run."],
    ["Referans tarama ", "Baseline scan "],
    [" yayın durumuyla tamamlandı.", " release status."],
    ["Politika kararı: ", "Policy decision: "],
    [", skor ", ", score "],
    [" alanında yayın riski buldu: ", " found release risk in "],
    [". Düzeltme adımları için ayrıntılı raporu aç.", ". Open the detailed report for remediation steps."],
    ["Güncellenmesi gereken paket: ", "Package requiring update: "],
    ["Paketi ", "Update the package to "],
    [" yükselt.", "."],
    ["Satır", "Line"],
    ["tür", "type"]
  ];

  const demos = new Set([
    "secure-demo-repo",
    "review-demo-repo",
    "cleanup-demo-repo",
    "critical-demo-repo"
  ]);

  function translateValue(value) {
    if (typeof value !== "string") return value;
    const leading = value.match(/^\s*/)?.[0] || "";
    const trailing = value.match(/\s*$/)?.[0] || "";
    let core = value.trim();
    if (!core) return value;

    if (exact.has(core)) return `${leading}${exact.get(core)}${trailing}`;

    let match = core.match(/^Gizli bilgi (\d+) \/ Bağımlılık (\d+) \/ Otomasyon (\d+) \/ İmza (.+)$/);
    if (match) return `${leading}Secrets ${match[1]} / Dependencies ${match[2]} / CI/CD ${match[3]} / Signature ${translateValue(match[4]).trim()}${trailing}`;

    match = core.match(/^(\d+) bulgu$/);
    if (match) return `${leading}${match[1]} finding${match[1] === "1" ? "" : "s"}${trailing}`;

    match = core.match(/^(\d+) paket güncellenmeli$/);
    if (match) return `${leading}${match[1]} package${match[1] === "1" ? "" : "s"} should be updated${trailing}`;

    match = core.match(/^Satır (\d+) • Gizli değer maskelendi$/);
    if (match) return `${leading}Line ${match[1]} • Secret value masked${trailing}`;

    match = core.match(/^Satır (\d+)$/);
    if (match) return `${leading}Line ${match[1]}${trailing}`;

    match = core.match(/^Satır (\d+) \/ tür (.+)$/);
    if (match) return `${leading}Line ${match[1]} / type ${match[2]}${trailing}`;

    match = core.match(/^Mevcut sürüm (.+) \/ önerilen sürüm (.+)$/);
    if (match) return `${leading}Current version ${match[1]} / recommended ${match[2]}${trailing}`;

    match = core.match(/^Mevcut (.+) \/ beklenen (.+)$/);
    if (match) return `${leading}Current ${match[1]} / expected ${match[2]}${trailing}`;

    match = core.match(/^Konum: (.+)$/);
    if (match) return `${leading}Location: ${match[1]}${trailing}`;

    match = core.match(/^Öne çıkan uyarı: (.+)\.$/);
    if (match) return `${leading}Top warning: ${translateValue(match[1]).trim()}.${trailing}`;

    match = core.match(/^Tarayıcı (\d+)$/);
    if (match) return `${leading}Scanner ${match[1]}${trailing}`;

    match = core.match(/^Uyarı (\d+)$/);
    if (match) return `${leading}Warning ${match[1]}${trailing}`;

    let translated = core;
    for (const [source, target] of partials) {
      if (translated.includes(source)) translated = translated.replaceAll(source, target);
    }
    if (translated !== core) return `${leading}${translated}${trailing}`;

    return value;
  }

  function translateElementAttributes(element) {
    if (!(element instanceof Element)) return;
    for (const name of ["placeholder", "title", "aria-label", "alt"]) {
      if (!element.hasAttribute(name)) continue;
      const current = element.getAttribute(name);
      const translated = translateValue(current);
      if (translated !== current) element.setAttribute(name, translated);
    }
  }

  function translateTree(root) {
    if (!root) return;
    if (root.nodeType === Node.TEXT_NODE) {
      const translated = translateValue(root.nodeValue || "");
      if (translated !== root.nodeValue) root.nodeValue = translated;
      return;
    }
    if (!(root instanceof Element) && root !== document.body) return;

    if (root instanceof Element) translateElementAttributes(root);
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT | NodeFilter.SHOW_ELEMENT);
    let node;
    while ((node = walker.nextNode())) {
      if (node.nodeType === Node.TEXT_NODE) {
        const translated = translateValue(node.nodeValue || "");
        if (translated !== node.nodeValue) node.nodeValue = translated;
      } else {
        translateElementAttributes(node);
      }
    }
  }

  function ensureDemoChips() {
    const form = document.querySelector("#repoForm");
    if (!form || form.querySelector(".scan-options")) return;

    const labels = [
      ["secure-demo-repo", "Secure demo"],
      ["review-demo-repo", "Review demo"],
      ["cleanup-demo-repo", "Cleanup demo"],
      ["critical-demo-repo", "Critical demo"]
    ];
    const wrap = document.createElement("div");
    wrap.className = "scan-options";
    wrap.setAttribute("aria-label", "Demo repositories");
    for (const [value, label] of labels) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "scan-chip";
      button.dataset.demoRepo = value;
      button.textContent = label;
      wrap.append(button);
    }
    form.append(wrap);
  }

  function repoNameFromUrl(value) {
    try {
      const url = new URL(value);
      const parts = url.pathname.split("/").filter(Boolean);
      return (parts[parts.length - 1] || "repository").replace(/\.git$/i, "");
    } catch {
      return "repository";
    }
  }

  function installStaticUrlPreview() {
    const form = document.querySelector("#repoForm");
    const input = document.querySelector("#repoUrl");
    if (!form || !input) return;

    form.addEventListener("submit", () => {
      const original = input.value.trim();
      if (!original || demos.has(original.toLowerCase())) return;

      let parsed;
      try { parsed = new URL(original); } catch { return; }
      if (!/^https?:$/.test(parsed.protocol) || !/(^|\.)github\.com$/i.test(parsed.hostname)) return;

      input.dataset.awsOriginalRepo = original;
      input.value = "review-demo-repo";

      setTimeout(() => {
        input.value = original;
        const name = repoNameFromUrl(original);
        const resultName = document.querySelector("#resultRepoName");
        const resultUrl = document.querySelector("#resultRepoUrl");
        if (resultName) resultName.textContent = name;
        if (resultUrl) resultUrl.textContent = original;

        const panel = document.querySelector("#resultView .result-panel");
        if (panel && !panel.querySelector(".aws-demo-note")) {
          const note = document.createElement("p");
          note.className = "aws-demo-note";
          note.textContent = "AWS static demo preview: this public deployment uses the built-in review scenario. The full local RepoGuard backend performs live repository scanning.";
          panel.append(note);
        }
        translateTree(document.body);
      }, 0);
    }, true);
  }

  function installClientSideAttackPreview() {
    document.addEventListener("click", (event) => {
      const actionButton = event.target.closest?.("[data-attack-action]");
      const resetButton = event.target.closest?.("[data-attack-reset]");
      if (!actionButton && !resetButton) return;

      event.preventDefault();
      event.stopImmediatePropagation();

      const output = document.querySelector("#attackOutput");
      if (!output) return;

      if (resetButton) {
        output.innerHTML = '<div class="mini-status-grid"><article class="mini-status-card"><span>Baseline</span><strong>94</strong><p>APPROVED</p></article><article class="mini-status-card"><span>Current</span><strong>94</strong><p>APPROVED</p></article><article class="mini-status-card"><span>Audit Chain</span><strong>Valid</strong><p>Reset</p></article></div><p class="attack-message">Baseline restored for the AWS client-side demo.</p>';
        return;
      }

      const action = actionButton.getAttribute("data-attack-action");
      const scenarios = {
        "tamper-release": [34, "FIX", "Release artifact tampering detected."],
        "leak-secret": [22, "BLOCKED", "A simulated secret exposure lowered the security score."],
        "risky-workflow": [48, "FIX", "A risky CI/CD permission change was detected."],
        "break-signature": [18, "BLOCKED", "Digital signature verification failed in the simulation."]
      };
      const [score, status, message] = scenarios[action] || [58, "REVIEW", "Security conditions changed in the simulation."];
      output.innerHTML = `<div class="mini-status-grid"><article class="mini-status-card"><span>Before</span><strong>94</strong><p>APPROVED</p></article><article class="mini-status-card"><span>After</span><strong>${score}</strong><p>${status}</p></article><article class="mini-status-card"><span>Audit Chain</span><strong>Valid</strong><p>Recorded</p></article></div><p class="attack-message">${message}</p>`;
    }, true);
  }

  function init() {
    ensureDemoChips();
    translateTree(document.body);
    document.title = "RepoGuard | Repository Security Analysis";

    installStaticUrlPreview();
    installClientSideAttackPreview();

    const observer = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        if (mutation.type === "characterData") {
          translateTree(mutation.target);
        } else if (mutation.type === "attributes") {
          translateElementAttributes(mutation.target);
        } else {
          for (const node of mutation.addedNodes) translateTree(node);
        }
      }
    });
    observer.observe(document.body, {
      subtree: true,
      childList: true,
      characterData: true,
      attributes: true,
      attributeFilter: ["placeholder", "title", "aria-label", "alt"]
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init, { once: true });
  } else {
    init();
  }
})();
