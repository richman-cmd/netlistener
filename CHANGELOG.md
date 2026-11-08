# Sürüm notları

## 0.03 — 9 Kasım 2026

### Yeni
- **Tek dosyalık `NetListener.exe`:** Python, `pip` ya da komut satırı gerekmez. Kurulum artık iki adım: Npcap'i kur, exe'yi indirip çift tıkla.
- Exe açılışta Windows yönetici iznini doğrudan ister (tek onay); siyah konsol penceresi hiç açılmaz.
- Exe'nin kendi simgesi ve sürüm bilgisi var (Özellikler → Ayrıntılar).
- GitHub Actions exe'yi her gönderimde Windows'ta derler, öz testten geçirir ve yayınlanan sürüme otomatik ekler.
- `--selftest` seçeneği: pencere açmadan exe'nin içindeki kütüphaneleri ve sürücü dosyalarını kontrol eder.

### Belgeler
- README'de "Kolay yol: NetListener.exe" kurulumu, SmartScreen ve antivirüs uyarıları, exe'yi kendin derleme adımları.

## 0.02 — 9 Kasım 2026

### Yeni
- Sistem tepsisi simgesi: pencerenin çarpısı programı kapatmaz, saatin yanındaki simgeye indirir. İzleme ve hız sınırları arka planda çalışmaya devam eder.
- Programı tamamen kapatmak için tepsi simgesine sağ tıklayıp **Çıkış**'ı seç.
- Tepsi simgesinin üzerine gelince anlık indirme/yükleme hızı ve açık sınır sayısı görünür; menüde de anlık hız yazar.
- İlk kez tepsiye inerken nasıl kapatılacağını anlatan bir Windows bildirimi çıkar.
- Tek kopya: program zaten açıkken yeniden çalıştırılırsa yeni kopya başlamaz, açık olan pencere öne gelir.
- Pencere gizliyken tablo ve grafik çizilmez, işlemci kullanımı düşer.
- Siyah konsol penceresi kalmaz: çift tıklamayla açıldığında program kendini konsolsuz (`pythonw`) yeniden başlatır. Komut İstemi'nden çalıştırıldığında konsola dokunulmaz. Hata kayıtları `%APPDATA%\NetWatch\netlistener.log` dosyasına yazılır.
- Daha önce ağ kullanmış ama şu an kullanmayan (pasif) programlar ve bağlantılar kırmızı görünür. Engelli programlar karışmasın diye ayrı bir üstü çizili simge ve kalın yazıyla gösterilir.

### Belgeler
- README'ye "Sık sorulan sorular" bölümü eklendi: "(bilinmeyen / sistem)" satırı, sık görülen adresler, renkler, tepsi, "yerel" etiketi, ayar dosyaları.

### Gereksinimler
- Yeni: `pystray`, `Pillow` (`pip install -r requirements.txt` ile kurulur). Yoksa program yine çalışır; çarpı pencereyi simge durumuna küçültür ve araç çubuğunda Çıkış düğmesi görünür.

## 0.01 — 17 Ekim 2026

İlk yayın.

### İzleme
- Program bazında canlı indirme/yükleme hızı, toplam trafikteki payı ve oturum toplamı
- Ağaç görünüm: Bilgisayar → Filtreler (İnternet, Yerel ağ) → Programlar → bağlantılar
- Her programın bağlandığı adresler, alan adıyla birlikte
- Tüm ağ bağdaştırıcıları aynı anda dinlenir (Ethernet, Wi-Fi, VPN, mobil paylaşım); yeni bağlananlar otomatik eklenir
- Bağdaştırıcı başına hız şeridi
- Son 60 ölçümün canlı grafiği; seçili program, filtre ya da toplam için
- Mbps / MB/s birim seçimi, yenileme aralığı, arama, sütuna göre sıralama

### Kontrol
- Hız sınırı: programa özel, İnternet'e özel, Yerel ağa özel ve tüm bilgisayar için genel
- Tablo içinden düzenleme: kutuya tıkla aç/kapat, değere tıkla yaz (`5`, `500k`, `2,5 Mbps`, `1 MB/s`, `yok`)
- Öncelik: Düşük / Normal / Yüksek / Kritik (bir sınır dolduğunda yüksek öncelik önce geçer)
- Sınırlar ve öncelikler kaydedilir, bir sonraki açılışta yeniden uygulanır
- Windows Güvenlik Duvarı ile bir programın internetini tamamen engelleme / engeli kaldırma
- Programı sonlandırma, dosya konumunu açma, ayrıntılar

### Gereksinimler
- Windows 10 / 11, Python 3.9+
- Npcap (WinPcap API uyumlu kip)
- `psutil`, `scapy`, `pydivert`
