# 🚀 MultiApp .NET Solution: Web, API & Performance Analysis

Bu repo; modern **.NET** mimarisi kullanılarak geliştirilmiş, **MVC Web Arayüzü** ve **RESTful API** servislerini içeren, performans metrikleri **Apache JMeter** ile test edilip raporlanmış kapsamlı bir full-stack çözümüdür.

![C#](https://img.shields.io/badge/C%23-239120?style=for-the-badge&logo=c-sharp&logoColor=white)
![.NET](https://img.shields.io/badge/.NET-512BD4?style=for-the-badge&logo=dotnet&logoColor=white)
![JMeter](https://img.shields.io/badge/JMeter-D22128?style=for-the-badge&logo=apachejmeter&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)

## 🎯 Proje Özeti ve Amacı

Bu proje, sadece işlevsel bir web uygulaması geliştirmeyi değil, aynı zamanda uygulamanın yoğun yük altındaki davranışlarını analiz etmeyi hedefler. Proje üç ana modülden oluşur:
1.  **MyWebApp:** Kullanıcı yönetimi, log görüntüleme ve dashboard işlemlerini içeren ASP.NET Core MVC arayüzü.
2.  **MyNewApiProject:** Dış servisler ve mobil entegrasyonlar için güvenli (JWT) veri akışı sağlayan Backend servisi.
3.  **Performance Lab:** Uygulamanın sınırlarını zorlayan JMeter test senaryoları ve analiz raporları.

## 🛠 Kullanılan Teknolojiler ve Mimari

* **Backend:** ASP.NET Core Web API & MVC (.NET 7/8)
* **Veritabanı:** Entity Framework Core (Code First Yaklaşımı)
* **Güvenlik (Auth):**
    * **JWT (JSON Web Token):** API güvenliği için.
    * **Custom Middleware:** `SingleSessionMiddleware` ile eşzamanlı oturum kontrolü.
* **Loglama:** NLog ile yapılandırılmış hata ve olay kaydı.
* **Test & Performans:** Apache JMeter (Load, Stress ve Spike testleri).
* **Frontend:** Bootstrap 5, jQuery, HTML5/CSS3.

## 📂 Proje Yapısı

```bash
MultiAppProject/
├── MyWebApp/               # MVC Frontend (Dashboard, Kullanıcı Yönetimi)
│   ├── Controllers/        # Home, Auth işlemleri
│   ├── Middleware/         # Oturum yönetimi kısıtlamaları
│   └── Views/              # Responsive kullanıcı arayüzleri
├── MyNewApiProject/        # Backend REST API
│   ├── Controllers/        # AuthController (Token işlemleri)
│   └── Data/               # DB Context ve Migrations
├── MyConsoleApp/           # Yardımcı araçlar ve test simülasyonları
└── JMeterTestResults/      # 📊 Yük Testi Raporları (PDF)
