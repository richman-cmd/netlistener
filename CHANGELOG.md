# Sürüm notları

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
