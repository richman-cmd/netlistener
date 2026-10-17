# NetListener

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

1. [Python 3](https://www.python.org/downloads/) kur. Kurulumda "Add Python to PATH" kutusunu işaretle.
2. [Npcap](https://npcap.com/#download) kur. Kurulumda **"Install Npcap in WinPcap API-compatible Mode"** işaretli olsun.
3. Komut İstemi'nde bağımlılıkları kur:
   ```
   pip install -r requirements.txt
   ```
4. `netlistener.py` dosyasına çift tıkla. Yönetici izni istenirse **Evet** de.

Konsol penceresi açılmasın istersen dosyanın uzantısını `.pyw` yap.

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
