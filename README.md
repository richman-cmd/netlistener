# NetListener

**Sürüm 0.02** · [Sürüm notları](CHANGELOG.md) · [İndir](https://github.com/richman-cmd/netlistener/releases/latest)

Windows için ağ izleme ve hız sınırlama aracı. Hangi programın interneti ne kadar kullandığını canlı gösterir; programlara, İnternet / Yerel ağ trafiğine ya da tüm bilgisayara indirme ve yükleme sınırı koymanı sağlar.

## Özellikler

- **Program bazında canlı trafik:** indirme/yükleme hızı (Mbps veya MB/s), toplamdaki payı, oturum toplamı
- **Ağaç görünüm:** Bilgisayar → Filtreler (İnternet, Yerel ağ) → Programlar → her programın bağlandığı adresler (alan adıyla)
- **Hız sınırı:** tablodaki kutuya tıklayarak aç/kapat, değere tıklayıp yaz (`5`, `500k`, `2,5 Mbps`, `1 MB/s`)
  - programa özel, İnternet'e ya da Yerel ağa özel, tüm bilgisayara genel
- **Öncelik:** Düşük / Normal / Yüksek / Kritik. Bir sınır dolduğunda yüksek öncelikli program önce geçer.
- **İnterneti tamamen engelleme:** Windows Güvenlik Duvarı kuralıyla, sağ tık menüsünden
- **Tüm bağdaştırıcılar:** Ethernet, Wi-Fi, VPN, mobil paylaşım. Sonradan bağlananlar otomatik eklenir.
- **Sistem tepsisi:** çarpı programı kapatmaz, saatin yanındaki simgeye indirir; izleme ve sınırlar çalışmaya devam eder. Çıkış yalnızca tepsi menüsünden.
- **Tek kopya:** program ikinci kez açılırsa yeni kopya başlamaz, açık olan pencere öne gelir.
- Canlı grafik, arama, sıralama, programı sonlandırma, dosya konumunu açma

## Kurulum

1. **İndir:** [Son sürüm sayfasından](https://github.com/richman-cmd/netlistener/releases/latest) `netlistener-0.02.zip` dosyasını indir ve bir klasöre çıkar.
2. **Python 3:** [python.org](https://www.python.org/downloads/) adresinden kur. Kurulumun ilk ekranında **"Add Python to PATH"** kutusunu işaretle.
3. **Npcap:** [npcap.com](https://npcap.com/#download) adresinden kur. Seçenekler ekranında **"Install Npcap in WinPcap API-compatible Mode"** işaretli olsun, diğer iki kutu boş kalabilir.
4. **Bağımlılıklar:** Zip'i çıkardığın klasörde adres çubuğuna `cmd` yazıp Enter'a bas, açılan pencerede şunu çalıştır:
   ```
   pip install -r requirements.txt
   ```
   Bu komut şu kütüphaneleri kurar: **psutil** (programları bulur), **scapy** (trafiği dinler), **pydivert** (hız sınırlayıcı), **pystray** ve **Pillow** (sistem tepsisi simgesi). İstersen tek tek de kurabilirsin:
   ```
   pip install psutil scapy pydivert pystray pillow
   ```
   pydivert olmadan program yine açılır ve trafiği gösterir, ama hız sınırı koyamazsın. pystray olmadan tepsi simgesi olmaz; o durumda çarpı pencereyi simge durumuna küçültür ve araç çubuğunda bir **Çıkış** düğmesi görünür.
5. **Çalıştır:** `netlistener.py` dosyasına çift tıkla. "Yönetici olarak yeniden başlatılsın mı?" sorusuna ve Windows'un izin penceresine **Evet** de.

Açılışta bir an görünen siyah konsol penceresi kendiliğinden kapanır; program arka planda (konsolsuz `pythonw` ile) çalışır ve yalnızca kendi penceresi ile tepsi simgesi kalır. Komut İstemi'nden `python netlistener.py` ile çalıştırırsan o pencereye dokunulmaz. Hata kayıtları `%APPDATA%\NetWatch\netlistener.log` dosyasına yazılır.

### Sorun giderme

| Belirti | Çözüm |
|---|---|
| "Paket dinlenemiyor" uyarısı | Npcap kurulu mu, program yönetici olarak mı açıldı, kontrol et |
| Tepsi simgesi yok, araç çubuğunda "Çıkış" düğmesi var | `pip install pystray pillow` çalıştır, programı yeniden aç |
| Saatin yanında simge görünmüyor | Görev çubuğundaki **^** okuna tıkla; simgeyi oradan görev çubuğuna sürükleyebilirsin |
| "pydivert kütüphanesi gerekiyor" | `pip install pydivert` çalıştır, programı yeniden aç |
| Hız sınırlayıcı hata veriyor | Programı yönetici olarak aç. Antivirüs WinDivert'i engelliyorsa izin ver |
| `pip` komutu bulunamadı | Python kurulumunda "Add Python to PATH" işaretlenmemiş; `py -m pip install -r requirements.txt` dene |
| Program açılmıyor, hiçbir pencere çıkmıyor | `%APPDATA%\NetWatch\netlistener.log` dosyasına bak; ya da Komut İstemi'nde `python netlistener.py` ile çalıştırıp hatayı gör |
| Liste boş kalıyor | Tarayıcıda bir sayfa açıp trafik oluştur; birkaç saniye bekle |

## Kullanım

**Listedeki renkler**

| Görünüm | Anlamı |
|---|---|
| 🟢 yeşil nokta, beyaz yazı | Şu an ağ kullanıyor |
| 🔴 kırmızı nokta, kırmızı yazı | Daha önce ağ kullandı, şu an kullanmıyor (pasif) |
| Yeşil yazı | Hız sınırı konmuş ve şu an ağ kullanıyor |
| ⛔ üstü çizili simge, kalın kırmızı yazı, "· engelli" | İnternet erişimi güvenlik duvarıyla engellenmiş |

| Ne yapmak istiyorsun | Nasıl |
|---|---|
| Sınırı aç / kapat | Sınır sütunundaki ☐ / ☑ kutusuna tıkla |
| Sınır değerini değiştir | Değere tıkla, yaz, Enter |
| Sınırı kaldır | Değere `yok` yaz ya da kutunun işaretini kaldır |
| Öncelik ver | Öncelik hücresine tıkla |
| Bir programın bağlantılarını gör | Programın solundaki oka tıkla |
| Grafikte göster | Satıra tıkla (Esc: toplama dön) |
| Engelle, sonlandır, ayrıntılar | Sağ tık |
| Pencereyi gizle | Çarpıya bas: program tepsiye iner, çalışmaya devam eder |
| Pencereyi geri aç | Tepsi simgesine tıkla ya da programı yeniden çalıştır |
| Programı tamamen kapat | Tepsi simgesine sağ tık → **Çıkış** |
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
