"""Suspicious URL checker — SYA201 egitim araci (stdlib only).
Kullanim: python checker.py "http://ornek.com/giris"
"""
import argparse
from urllib.parse import urlparse

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"}
RISKY_TLD = {"tk", "ml", "ga", "cf", "gq", "top", "xyz", "click"}
LOGIN_WORDS = {"login", "giris", "verify", "dogrula", "bank", "hesap", "password"}


def check(url: str) -> tuple[int, list[str]]:
    if "://" not in url:
        url = "http://" + url
    p = urlparse(url)
    host = p.hostname or ""
    skor, neden = 0, []

    def ekle(puan: int, aciklama: str) -> None:
        nonlocal skor
        skor += puan
        neden.append(f"+{puan} {aciklama}")

    is_ip = False
    try:
        parts = host.split(".")
        if len(parts) == 4 and all(x.isdigit() for x in parts):
            is_ip = True
            ekle(3, "IP adresi host olarak kullanilmis")
    except Exception:
        pass
    if "@" in url:
        ekle(3, "@ isareti var (kimlik gizleme)")
    if host.startswith("xn--") or ".xn--" in host:
        ekle(2, "Punycode (uluslararasi) alan adi")
    if host in SHORTENERS:
        ekle(2, "URL kisaltma servisi")
    if "." in host and host.rsplit(".", 1)[-1] in RISKY_TLD:
        ekle(2, "Riskli ust seviye alan adi")
    if not is_ip and host.count(".") >= 3:
        ekle(1, "Asiri alt alan adi")
    if host.count("-") >= 3:
        ekle(1, "Asiri tire (taklit suphesi)")
    if p.scheme == "http":
        ekle(1, "Sifresiz HTTP")
    yol = (p.path + "?" + p.query).lower()
    if any(w in yol for w in LOGIN_WORDS):
        ekle(1, "Giris/banka kelimesi iceriyor")

    if skor >= 5:
        karar = "TEHLIKELI"
    elif skor >= 3:
        karar = "SUPHELI"
    else:
        karar = "TEMIZ GORUNUYOR"
    return skor, neden + [f"Karar: {karar}"]


def main() -> None:
    ap = argparse.ArgumentParser(description="Supheli URL denetimi (egitim amacli)")
    ap.add_argument("url", help="Denetlenecek adres")
    args = ap.parse_args()
    skor, satirlar = check(args.url)
    print(f"Skor: {skor}")
    for s in satirlar:
        print(f" - {s}")


if __name__ == "__main__":
    main()
