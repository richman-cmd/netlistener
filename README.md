# NetListener

**Sürüm 0.03** · [Sürüm notları](CHANGELOG.md) · [İndir](https://github.com/richman-cmd/netlistener/releases/latest)

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

### Kolay yol: NetListener.exe (önerilen)

Python ya da komut satırı gerekmez.

1. **Npcap'i kur:** [npcap.com](https://npcap.com/#download) adresinden indir. Seçenekler ekranında **"Install Npcap in WinPcap API-compatible Mode"** işaretli olsun, diğer iki kutu boş kalabilir.
   *Npcap'in lisansı NetListener'ın içinde dağıtılmasına izin vermediği için ayrıca kurulması gerekiyor.*
2. **NetListener.exe'yi indir:** [Son sürüm sayfasından](https://github.com/richman-cmd/netlistener/releases/latest) `NetListener.exe` dosyasını indir ve istediğin bir klasöre (ör. Belgeler) koy.
3. **Çalıştır:** Çift tıkla, Windows'un yönetici izni penceresine **Evet** de.

İlk açılışta iki uyarı görebilirsin; ikisi de exe imzalı olmadığı için çıkar:

- **"Windows kişisel bilgisayarınızı korudu"** (SmartScreen): **Ek bilgi** → **Yine de çalıştır**.
- **Antivirüs uyarısı:** NetListener hız sınırı için ağ paketlerine müdahale eden WinDivert sürücüsünü kullanır; bazı antivirüsler bu yüzden "şüpheli araç" der. Kaynak kodu bu depoda açıktır. NetListener'a izin verip istisnalara ekleyebilirsin.

Kısayol için `NetListener.exe`'ye sağ tıkla → **Gönder** → **Masaüstü (kısayol oluştur)**.

### Python ile (geliştiriciler için)

1. **Kodu indir:** [Son sürüm sayfasından](https://github.com/richman-cmd/netlistener/releases/latest) zip dosyasını indir ve bir klasöre çıkar.
2. **Python 3:** [python.org](https://www.python.org/downloads/) adresinden kur. Kurulumun ilk ekranında **"Add Python to PATH"** kutusunu işaretle.
3. **Npcap:** yukarıdaki gibi kur.
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

Açılışta bir an görünen siyah konsol penceresi kendiliğinden kapanır; program arka planda (konsolsuz `pythonw` ile) çalışır. Komut İstemi'nden `python netlistener.py` ile çalıştırırsan o pencereye dokunulmaz. Hata kayıtları `%APPDATA%\NetWatch\netlistener.log` dosyasına yazılır.

### Exe'yi kendin derlemek

Windows'ta, depo klasöründe:
```
pip install -r requirements.txt pyinstaller
python build/build_exe.py
```
Sonuç `dist\NetListener.exe` olur. GitHub Actions aynı işi her gönderimde yapar: exe'yi derler, `--selftest` ile içindeki kütüphaneleri ve sürücü dosyalarını kontrol eder, Actions sayfasına yükler; bir sürüm yayınlandığında exe'yi sürüm sayfasına otomatik ekler.

### Sorun giderme

| Belirti | Çözüm |
|---|---|
| "Windows kişisel bilgisayarınızı korudu" | **Ek bilgi** → **Yine de çalıştır** (exe imzalı olmadığı için çıkar) |
| Antivirüs exe'yi siliyor ya da karantinaya alıyor | Karantinadan geri yükle ve NetListener.exe'yi istisnalara ekle |
| "Paket dinlenemiyor" uyarısı | Npcap kurulu mu, program yönetici olarak mı açıldı, kontrol et |
| Tepsi simgesi yok, araç çubuğunda "Çıkış" düğmesi var | `pip install pystray pillow` çalıştır, programı yeniden aç |
| Saatin yanında simge görünmüyor | Görev çubuğundaki **^** okuna tıkla; simgeyi oradan görev çubuğuna sürükleyebilirsin |
| "Hız sınırlayıcı yüklenemedi" (exe) | Antivirüs WinDivert sürücüsünü engellemiş olabilir; NetListener'a izin ver |
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

## Sık sorulan sorular

### "(bilinmeyen / sistem)" satırı ne?

NetListener'ın hangi programa ait olduğunu tespit edemediği trafik. Bir sorun ya da tehlike işareti değildir; genellikle toplam trafiğin çok küçük bir kısmıdır. Üç sebebi olabilir:

1. **Yeni bağlantıların ilk paketleri:** Açık bağlantıların listesi saniyede iki kez yenilenir. Bir program yeni bağlantı açtığında ilk birkaç paket liste yenilenmeden gelirse sahibi henüz bilinmez.
2. **Çok kısa süren bağlantılar:** Bir anda açılıp kapanan bağlantılar listeye hiç girmeden bitebilir.
3. **Windows servisleri:** Bazı sistem trafiğinin sahibi Windows tarafından gösterilmez.

Satırın solundaki oka tıklayınca bu trafiğin hangi adreslere gittiği görünür. Sık rastlanan adresler:

| Adres | Ne olduğu |
|---|---|
| `239.255.255.250:1900` · yerel | Windows'un evdeki cihazları (modem, TV, yazıcı) araması (UPnP / SSDP) |
| `224.0.0.252:5355` · yerel | Windows'un yerel ağda bilgisayar adı sorgulaması (LLMNR) |
| `224.0.0.251:5353` · yerel | Yerel ağda cihaz keşfi (mDNS) |
| `dns.google:443` | Güvenli DNS: tarayıcı ya da Windows site adreslerini Google'a şifreli soruyor |
| `...1e100.net` | Google sunucuları |
| `...amazonaws.com` | Amazon bulut sunucuları; pek çok uygulama ve site burada çalışır |
| `104.16.x – 104.31.x`, `162.159.x` | Cloudflare; Discord dahil birçok site bunun arkasındadır |

### Satırlar neden kırmızı?

Kırmızı satır, o programın (ya da bağlantının) bu oturumda daha önce ağ kullandığını ama şu an kullanmadığını gösterir. Program yeniden ağ kullanmaya başlayınca yeşil noktaya döner. Renklerin tamamı için yukarıdaki **Listedeki renkler** tablosuna bak.

### Çarpıya bastım, program kapandı mı?

Hayır, saatin yanındaki tepsi simgesine indi; izleme ve hız sınırları çalışmaya devam ediyor. Tamamen kapatmak için tepsi simgesine sağ tıklayıp **Çıkış**'ı seç.

### "yerel" etiketi ne demek?

O bağlantı internete değil, evdeki/ofisteki ağa (modem, diğer bilgisayarlar, yazıcı, NAS) gidiyor demektir. İnternet'e konan hız sınırı bu trafiği etkilemez; ayrı sınır için **Filtreler → Yerel ağ** satırını kullan.

### Ayarlarım nerede saklanıyor?

`%APPDATA%\NetWatch\` klasöründe:

| Dosya | İçeriği |
|---|---|
| `limitler.json` | Hız sınırları ve öncelikler |
| `engellenenler.json` | İnterneti engellenen programlar |
| `netlistener.log` | Hata kayıtları |

Klasörün adı eski sürümle uyum için `NetWatch` olarak kaldı.

## Nasıl çalışır

- **İzleme:** [scapy](https://scapy.net/) ve Npcap ile tüm bağdaştırıcılardaki paketler dinlenir. Her paket, yerel port numarası üzerinden [psutil](https://github.com/giampaolo/psutil) ile sahibi olan programa eşlenir.
- **Hız sınırı:** [pydivert](https://github.com/ffalcinelli/pydivert) (WinDivert sürücüsü) paketleri yakalar. Program, filtre ve genel sınırlar için ayrı jeton kovaları tutar ve sınırı aşan paketleri sıraya alıp geciktirir. Sürücü yalnızca en az bir sınır açıkken çalışır.
- **Engelleme:** `netsh advfirewall` ile programa özel gelen/giden engelleme kuralı eklenir.

Sınırlar, öncelikler ve engellenen programların listesi `%APPDATA%\NetWatch\` klasöründe saklanır. Sınırlar program kapanınca kalkar, bir sonraki açılışta yeniden uygulanır. Güvenlik duvarı engelleri ise siz kaldırana kadar kalır.

## Bilinen sınırlamalar

- Hız sınırlayıcı yalnızca Windows'ta çalışır. İzleme Linux ve macOS'ta da çalışır (`sudo` ile).
- İndirme sınırı paketleri geciktirerek çalışır. Bir indirme başladığında hız ilk bir iki saniye sınırın biraz üstüne çıkabilir, sonra oturur.
- Yeni açılan bağlantıların ilk paketleri ve çok kısa süren bağlantılar bazen bir programa eşlenemez. Bu trafik "(bilinmeyen / sistem)" satırında görünür (ayrıntı için [Sık sorulan sorular](#bilinmeyen--sistem-satırı-ne)).
- VPN kullanırken aynı trafik hem VPN programında hem de asıl uygulamada görünür.
- Bazı antivirüs programları WinDivert sürücüsünü "şüpheli araç" olarak işaretleyebilir.
