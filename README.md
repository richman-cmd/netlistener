# NetListener

**Sürüm 0.01** · [Sürüm notları](CHANGELOG.md) · [İndir](https://github.com/richman-cmd/netlistener/releases/latest)

Windows için ağ izleme ve hız sınırlama aracı. Hangi programın interneti ne kadar kullandığını canlı gösterir; programlara, İnternet / Yerel ağ trafiğine ya da tüm bilgisayara indirme ve yükleme sınırı koymanı sağlar.

## Özellikler

- **Program bazında canlı trafik:** indirme/yükleme hızı (Mbps veya MB/s), toplamdaki payı, oturum toplamı
- **Ağaç görünüm:** Bilgisayar → Filtreler (İnternet, Yerel ağ) → Programlar → her programın bağlandığı adresler (alan adıyla)
- **Hız sınırı:** tablodaki kutuya tıklayarak aç/kapat, değere tıklayıp yaz (`5`, `500k`, `2,5 Mbps`, `1 MB/s`)
  - programa özel, İnternet'e ya da Yerel ağa özel, tüm bilgisayara genel
- **Öncelik:** Düşük / Normal / Yüksek / Kritik. Bir sınır dolduğunda yüksek öncelikli program önce geçer.
- **İnterneti tamamen engelleme:** Windows Güvenlik Duvarı kuralıyla, sağ tık menüsünden
- **Tüm bağdaştırıcılar:** Ethernet, Wi-Fi, VPN, mobil paylaşım. Sonradan bağlananlar otomatik eklenir.
- Canlı grafik, arama, sıralama, programı sonlandırma, dosya konumunu açma

## Kurulum

1. **İndir:** [Son sürüm sayfasından](https://github.com/richman-cmd/netlistener/releases/latest) `netlistener-0.01.zip` dosyasını indir ve bir klasöre çıkar.
2. **Python 3:** [python.org](https://www.python.org/downloads/) adresinden kur. Kurulumun ilk ekranında **"Add Python to PATH"** kutusunu işaretle.
3. **Npcap:** [npcap.com](https://npcap.com/#download) adresinden kur. Seçenekler ekranında **"Install Npcap in WinPcap API-compatible Mode"** işaretli olsun, diğer iki kutu boş kalabilir.
4. **Bağımlılıklar:** Zip'i çıkardığın klasörde adres çubuğuna `cmd` yazıp Enter'a bas, açılan pencerede şunu çalıştır:
   ```
   pip install -r requirements.txt
   ```
5. **Çalıştır:** `netlistener.py` dosyasına çift tıkla. "Yönetici olarak yeniden başlatılsın mı?" sorusuna ve Windows'un izin penceresine **Evet** de.

Konsol penceresi açılmasın istersen dosyanın uzantısını `.pyw` yap.

### Sorun giderme

| Belirti | Çözüm |
|---|---|
| "Paket dinlenemiyor" uyarısı | Npcap kurulu mu, program yönetici olarak mı açıldı, kontrol et |
| "pydivert kütüphanesi gerekiyor" | `pip install pydivert` çalıştır, programı yeniden aç |
| Hız sınırlayıcı hata veriyor | Programı yönetici olarak aç. Antivirüs WinDivert'i engelliyorsa izin ver |
| `pip` komutu bulunamadı | Python kurulumunda "Add Python to PATH" işaretlenmemiş; `py -m pip install -r requirements.txt` dene |
| Liste boş kalıyor | Tarayıcıda bir sayfa açıp trafik oluştur; birkaç saniye bekle |

## Kullanım

| Ne yapmak istiyorsun | Nasıl |
|---|---|
| Sınırı aç / kapat | Sınır sütunundaki ☐ / ☑ kutusuna tıkla |
| Sınır değerini değiştir | Değere tıkla, yaz, Enter |
| Sınırı kaldır | Değere `yok` yaz ya da kutunun işaretini kaldır |
| Öncelik ver | Öncelik hücresine tıkla |
| Bir programın bağlantılarını gör | Programın solundaki oka tıkla |
| Grafikte göster | Satıra tıkla (Esc: toplama dön) |
| Engelle, sonlandır, ayrıntılar | Sağ tık |
| Sırala | Sütun başlığına tıkla |

## Nasıl çalışır

- **İzleme:** [scapy](https://scapy.net/) ve Npcap ile tüm bağdaştırıcılardaki paketler dinlenir. Her paket, yerel port numarası üzerinden [psutil](https://github.com/giampaolo/psutil) ile sahibi olan programa eşlenir.
- **Hız sınırı:** [pydivert](https://github.com/ffalcinelli/pydivert) (WinDivert sürücüsü) paketleri yakalar. Program, filtre ve genel sınırlar için ayrı jeton kovaları tutar ve sınırı aşan paketleri sıraya alıp geciktirir. Sürücü yalnızca en az bir sınır açıkken çalışır.
- **Engelleme:** `netsh advfirewall` ile programa özel gelen/giden engelleme kuralı eklenir.

Sınırlar, öncelikler ve engellenen programların listesi `%APPDATA%\NetWatch\` klasöründe saklanır. Sınırlar program kapanınca kalkar, bir sonraki açılışta yeniden uygulanır. Güvenlik duvarı engelleri ise siz kaldırana kadar kalır.

## Bilinen sınırlamalar

- Hız sınırlayıcı yalnızca Windows'ta çalışır. İzleme Linux ve macOS'ta da çalışır (`sudo` ile).
- İndirme sınırı paketleri geciktirerek çalışır. Bir indirme başladığında hız ilk bir iki saniye sınırın biraz üstüne çıkabilir, sonra oturur.
- Çok kısa süren bağlantılar bazen bir programa eşlenemez. Bu trafik "(bilinmeyen / sistem)" satırında görünür.
- VPN kullanırken aynı trafik hem VPN programında hem de asıl uygulamada görünür.
- Bazı antivirüs programları WinDivert sürücüsünü "şüpheli araç" olarak işaretleyebilir.
