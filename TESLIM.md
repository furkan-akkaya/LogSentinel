# LogEssential 1.2.0b1 teslim notu

LogEssential, eski adıyla LogSentinel, yerel kullanım için beta olarak hazırlanır.
Paket adı, GitHub deposu, veritabanı yolu ve Compose servisi değişmez.
Detection Lab, Case Notes ve veri bağlamı yerel v1.2 çalışmasından gelir.

1. Kurulum ve kullanım için README.md dosyasını izle.
2. Güncellemeden önce servisi durdur ve veritabanını yedekle.
3. Docker güncellemesinde `down -v` kullanma.
4. Yükseltme ve geri dönüş için docs/RELEASE.md dosyasını izle.
5. Çalıştırılan kontroller için docs/VALIDATION_PUBLIC_BETA.md dosyasını oku.
6. Son commit CI sonucunu ve indirilen paket özetlerini yayın raporundan kontrol et.

Servisi yalnız loopback adresinde çalıştır.
Kimlik doğrulama ve yetkilendirme yoktur.
Kayıtlar ve notlar açık metin saklanır.
Case Notes değiştirilebilir; değişmez denetim geçmişi sağlamaz.
Canlı kayıt toplama ve ham EVTX desteği yoktur.
Windows kayıt biçimleri test edildi; gerçek Windows çalıştırması yapılmadı.
