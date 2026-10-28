# LogSentinel v1.1.0 teslim notu

1. Windows importu, açıkça yanlış kanal veya sağlayıcı içeren 4624/4625 kayıtlarını reddeder. XML Provider öznitelikleri de kontrol edilir.
2. Eksik kaynak alanları, belgelenmiş uyumluluk kapsamında kabul edilir. Kabul, kaynağın gerçekliğini kanıtlamaz.
3. Uyarı ayrıntısı gerçek kanıt sayısını, korelasyon kimliğini, eşiği ve zaman penceresini gösterir. Windows domain ve logon type görünür.
4. Normal açıklamalar, analist önerileri ve kural sınırları eklendi. Uygulama bu önerilen kontrolleri otomatik yapmaz.
5. Çalışma akışı, beş açıklamalı senaryo ve sentetik SSH inceleme raporu hazır. Belgeler gerçek kayıtlarla ve motor sonuçlarıyla karşılaştırılır.
6. İngilizce README yenilendi. Türkçe sunum anlatısı `docs/PORTFOLIO.md` içindedir. Rehberler uygulamadaki **Project guide** bağlantısından açılır.
7. Başlangıçtaki 67 test bu oturumda tekrar çalıştırıldı. Güncel 117 test macOS Python 3.11/3.13 ve Linux ARM64 üzerinde geçti.
8. Güncel paket içindeki 38 Windows kaynak testi ayrıca geçti. Chromium, mobil düzen, klavye akışı ve ayrı Docker kalıcılık kontrolü geçti.
9. Varsayılan demo sonucu değişmedi: 85 olay ve beş uyarı. İkinci yükleme 85 tekrar bildirir; yeni olay eklemez.
10. Eski v1.0.0 ZIP korunur. Yeni ZIP ve onun SHA-256 dosyası ayrı teslim edilir. GitHub'a push veya yayımlama yapılmadı.

Kurulum: Proje klasöründe `docker compose up --build -d` çalıştır. `http://127.0.0.1:8765` adresini aç.

Sınırlar: EVTX yok. Windows çalıştırma testi yapılmadı. Parola püskürtme ve dağıtılmış denemeler farklı kimliklerde kalır. Başarılı giriş, hesap ele geçirilmesini kanıtlamaz.

Uygulamada kimlik doğrulama yok. Ham loglar şifrelenmeden saklanır. Uygulamayı internete veya ortak ağa açma.
