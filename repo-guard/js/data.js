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
  start: "Hazır",
  loading: "Analiz ediliyor",
  danger: "Kritik Risk",
  caution: "Dikkat",
  controlled: "Kontrollü",
  curious: "Kontrollü",
  safe: "Güvenli"
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
    title: "Analiz bekleniyor",
    body: "RepoGuard, seçilen güvenlik puanını pastel alarm paneline dönüştürmeye hazır.",
    mascotAlt: "RepoGuard analiz bekleyen tavşan maskotu"
  },
  loading: {
    title: "Repo taranıyor",
    body: "Secret, bağımlılık, CI/CD ve bütünlük kontrolleri birlikte değerlendiriliyor.",
    mascotAlt: "RepoGuard yükleme durumundaki tavşan maskotu"
  },
  danger: {
    title: "Kritik Risk",
    body: "Bu repo yayınlanmadan önce düzeltilmeli. Hash uyuşmazlığı, geçersiz imza, secret sızıntısı veya riskli CI/CD ayarları tespit edildi.",
    mascotAlt: "Kırık kalkan tutan paniklemiş RepoGuard tavşanı"
  },
  caution: {
    title: "Dikkat",
    body: "Bazı kontroller alarm üretiyor. Yayın öncesi bulgular gözden geçirilmeli.",
    mascotAlt: "Kırık kalkanın yanında endişeli duran RepoGuard tavşan maskotu"
  },
  controlled: {
    title: "Kontrollü",
    body: "Genel durum fena değil. Yine de imza, secret ve CI/CD ayarlarını bir kez daha gözden geçirelim.",
    mascotAlt: "Büyüteçle inceleme yapan düşünceli RepoGuard tavşan maskotu"
  },
  safe: {
    title: "Güvenli",
    body: "Kontroller temiz. Repo yayın hattı için sağlıklı ve sakin görünüyor.",
    mascotAlt: "RepoGuard güvenli durum tavşan maskotu"
  }
};

export const CHECK_RESULTS = {
  start: [
    {
      title: "Secret taraması",
      value: "Beklemede",
      tone: "search",
      detail: "Token ve anahtar izleri analiz sırasında listelenir."
    },
    {
      title: "Bağımlılıklar",
      value: "Beklemede",
      tone: "search",
      detail: "Riskli paket sürümleri seçilen skora göre özetlenir."
    },
    {
      title: "CI/CD politikası",
      value: "Beklemede",
      tone: "search",
      detail: "Workflow izinleri ve tehlikeli komutlar kontrol edilir."
    },
    {
      title: "Bütünlük",
      value: "Beklemede",
      tone: "search",
      detail: "Hash, imza ve manifest sinyalleri birlikte izlenir."
    }
  ],
  loading: [
    {
      title: "Secret taraması",
      value: "Taranıyor",
      tone: "loading",
      detail: "Kaynak dosyalarda hassas veri kalıpları aranıyor."
    },
    {
      title: "Bağımlılıklar",
      value: "Taranıyor",
      tone: "loading",
      detail: "Paket sürümleri bilinen risklerle karşılaştırılıyor."
    },
    {
      title: "CI/CD politikası",
      value: "Taranıyor",
      tone: "loading",
      detail: "Pipeline ayarları yayın güvenliği için inceleniyor."
    },
    {
      title: "Bütünlük",
      value: "Taranıyor",
      tone: "loading",
      detail: "Manifest, SHA-256 ve imza durumu yenileniyor."
    }
  ],
  danger: [
    {
      title: "SHA-256",
      value: "Başarısız",
      tone: "danger",
      detail: "Hash uyuşmazlığı yayın kararını bloke ediyor."
    },
    {
      title: "Dijital İmza",
      value: "Geçersiz",
      tone: "danger",
      detail: "İmza doğrulaması geçerli güven sinyali üretmiyor."
    },
    {
      title: "Secret Taraması",
      value: "Kritik Secret Bulundu",
      tone: "danger",
      detail: "Sızıntı sinyali güçlü. Anahtarlar iptal edilip repo temizlenmeli."
    },
    {
      title: "CI/CD",
      value: "Yüksek Risk",
      tone: "danger",
      detail: "Yazma izni veya güvensiz komutlar yayın hattını kırıyor."
    },
    {
      title: "Bağımlılıklar",
      value: "Riskli Paket Bulundu",
      tone: "danger",
      detail: "Bilinen açıklar yayın kararını doğrudan etkiliyor."
    }
  ],
  caution: [
    {
      title: "Secret taraması",
      value: "Uyarı",
      tone: "caution",
      detail: "Şüpheli değerler var. Gerçek secret olup olmadığı doğrulanmalı."
    },
    {
      title: "Bağımlılıklar",
      value: "Uyarı",
      tone: "caution",
      detail: "Güncelleme bekleyen paketler güvenlik notunu düşürüyor."
    },
    {
      title: "CI/CD politikası",
      value: "Sınırlı risk",
      tone: "caution",
      detail: "Workflow ayarları daha sıkı bir yayın profiline alınmalı."
    },
    {
      title: "Bütünlük",
      value: "İzlemede",
      tone: "caution",
      detail: "Kriptografik sinyaller çalışıyor, ancak karar düşük güvenle veriliyor."
    }
  ],
  controlled: [
    {
      title: "SHA-256",
      value: "Geçti",
      tone: "safe",
      detail: "Hash kontrolü beklenen güven sinyalini üretiyor."
    },
    {
      title: "Dijital İmza",
      value: "Kontrol Et",
      tone: "controlled",
      detail: "İmza durumu kesin karar öncesi yeniden doğrulanmalı."
    },
    {
      title: "Secret Taraması",
      value: "İzlenmeli",
      tone: "attention",
      detail: "Kritik sızıntı yok, fakat şüpheli desenler gözden geçirilmeli."
    },
    {
      title: "CI/CD",
      value: "Dikkatli İncele",
      tone: "attention",
      detail: "Workflow ayarları kabul edilebilir, yine de yayın öncesi incelenmeli."
    }
  ],
  safe: [
    {
      title: "Secret taraması",
      value: "Temiz",
      tone: "safe",
      detail: "Secret kalıbı bulunmadı."
    },
    {
      title: "Bağımlılıklar",
      value: "Temiz",
      tone: "safe",
      detail: "Bilinen riskli bağımlılık görünmüyor."
    },
    {
      title: "CI/CD politikası",
      value: "Güvenli",
      tone: "safe",
      detail: "Workflow izinleri yayın için sağlıklı."
    },
    {
      title: "Bütünlük",
      value: "Doğrulandı",
      tone: "safe",
      detail: "SHA-256, manifest ve dijital imza eşleşiyor."
    }
  ]
};
