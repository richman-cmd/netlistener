"""
NetListener'ı tek dosyalık Windows programına (NetListener.exe) dönüştürür.

Windows'ta, depo klasöründe:
    pip install -r requirements.txt pyinstaller
    python build/build_exe.py

Sonuç: dist/NetListener.exe
  - Python kurulumu gerektirmez (her şey içinde)
  - Konsol penceresi açmaz
  - Açılırken Windows yönetici izni ister (tek onay)
  - Npcap yine ayrıca kurulmalıdır (lisansı programla birlikte dağıtılmasına izin vermiyor)

GitHub Actions bu betiği her gönderimde çalıştırır (.github/workflows/build.yml).
"""

import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD = os.path.join(ROOT, "build")
SOURCE = os.path.join(ROOT, "netlistener.py")


def read_version():
    with open(SOURCE, encoding="utf-8") as f:
        m = re.search(r'^__version__ = "([^"]+)"', f.read(), re.M)
    if not m:
        sys.exit("netlistener.py içinde __version__ bulunamadı")
    return m.group(1)


def make_icon(path):
    """Tepsi simgesiyle aynı görselden çok boyutlu .ico üretir."""
    sys.path.insert(0, ROOT)
    import netlistener  # noqa: E402  (yalnızca tray_image için)

    img = netlistener.tray_image(256)
    img.save(path, sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])


def make_version_file(path, version):
    nums = [int(x) for x in re.findall(r"\d+", version)][:4]
    nums += [0] * (4 - len(nums))
    t = tuple(nums)
    content = f"""VSVersionInfo(
  ffi=FixedFileInfo(filevers={t}, prodvers={t}, mask=0x3f, flags=0x0, OS=0x40004,
                    fileType=0x1, subtype=0x0, date=(0, 0)),
  kids=[
    StringFileInfo([StringTable('041f04b0', [
      StringStruct('CompanyName', 'NetListener'),
      StringStruct('FileDescription', 'NetListener - ağ izleme ve hız sınırlama'),
      StringStruct('FileVersion', '{version}'),
      StringStruct('InternalName', 'NetListener'),
      StringStruct('LegalCopyright', 'github.com/richman-cmd/netlistener'),
      StringStruct('OriginalFilename', 'NetListener.exe'),
      StringStruct('ProductName', 'NetListener'),
      StringStruct('ProductVersion', '{version}')])]),
    VarFileInfo([VarStruct('Translation', [0x041f, 1200])])
  ]
)
"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def main():
    if os.name != "nt":
        sys.exit("Bu betik Windows'ta çalıştırılmalıdır (exe Windows'ta derlenir).")
    version = read_version()
    icon = os.path.join(BUILD, "netlistener.ico")
    vfile = os.path.join(BUILD, "version_info.txt")
    make_icon(icon)
    make_version_file(vfile, version)

    args = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--clean",
        "--onefile",                 # tek dosya
        "--windowed",                # konsol penceresi yok
        "--uac-admin",               # açılışta yönetici izni iste
        "--name", "NetListener",
        "--icon", icon,
        "--version-file", vfile,
        "--distpath", os.path.join(ROOT, "dist"),
        "--workpath", os.path.join(BUILD, "pyinstaller"),
        "--specpath", os.path.join(BUILD, "pyinstaller"),
        # Dinamik yüklenen ya da veri dosyası olan paketler:
        "--collect-all", "pydivert",           # WinDivert64.dll / WinDivert64.sys
        "--collect-submodules", "scapy",       # scapy katmanları dinamik yüklenir
        "--hidden-import", "pystray._win32",   # tepsi simgesinin Windows arka ucu
        "--hidden-import", "PIL.ImageTk",
        "--exclude-module", "pydivert.tests",
        SOURCE,
    ]
    print("Çalıştırılıyor:", " ".join(args), flush=True)
    subprocess.run(args, check=True, cwd=ROOT)
    exe = os.path.join(ROOT, "dist", "NetListener.exe")
    print(f"\nHazır: {exe}  ({os.path.getsize(exe) / 1e6:.1f} MB, sürüm {version})")


if __name__ == "__main__":
    main()
