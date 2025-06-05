import cv2
import os
import glob
import time
import numpy as np
from PIL import Image
from PIL.ExifTags import TAGS
import hashlib

# === EINSTELLUNGEN ===
ORDNER = "extrahierte_bilder"
NAME = "HKX Extract and View CameraStream"
START_FPS = 15
#FARBE = (0, 170, 0)  # Matrix-Grün (BGR)
FARBE = (176, 60, 60)
FARBE_ROT = (35, 35, 122)
FARBE_GRUEN = (25, 255, 21)
FARBE_TITLE = FARBE_ROT
FARBE_VALUE = (255, 255, 255)

METADATEN_BREITE = 400  # Breite rechts für Textinfo

def berechne_komplementaer(farbe):
    return tuple(255 - wert for wert in farbe)

# === HILFSFUNKTION: EXIF LESEN ===
def exif_info(pfad):
    try:
        bild = Image.open(pfad)
        exif_daten = bild._getexif()
        if not exif_daten:
            return ["Keine EXIF-Daten vorhanden."]
        infos = []
        for tag_id, wert in exif_daten.items():
            tag = TAGS.get(tag_id, tag_id)
            infos.append(f" {tag} = {wert}")
            if len(infos) >= 15:  # max 15 Zeilen
                break
        return infos
    except Exception as e:
        return [f"EXIF-Fehler: {str(e)}"]

# === HILFSFUNKTION: SHA256 HASH ===
def sha256_hash(pfad):
    hash_sha256 = hashlib.sha256()
    with open(pfad, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

def calculate_md5(filepath):
    hash_md5 = hashlib.md5()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def init_image_viewer():
    # === BILDER LADEN ===
    bilder = sorted(glob.glob(os.path.join(ORDNER, '*.jpg'))) + sorted(glob.glob(os.path.join(ORDNER, '*.png')))
    if not bilder:
        print("Keine Bilder gefunden.")
        exit()

    # === INITIALISIERUNG ===
    cv2.namedWindow(NAME, cv2.WINDOW_NORMAL)
    cv2.resizeWindow(NAME, 1100, 550)

    fps = START_FPS
    index = 0
    pause = False
    rueckwaerts = False
    negativ = False

    while True:
        pfad = bilder[index]
        bild = cv2.imread(pfad)
        if bild is None:
            index = (index + 1) % len(bilder)
            continue

        hoehe, breite = bild.shape[:2]

        # === FRAME-BILD ===
        frame = cv2.resize(bild, (breite, hoehe))
        if negativ:
            frame = cv2.bitwise_not(frame)

        # === METADATEN-BILD erstellen ===
        meta_img = np.zeros((hoehe, METADATEN_BREITE, 3), dtype=np.uint8)

        # Bildinfos
        zeilen = []
        #zeilen.append("[ Informationen ]--")
        zeilen.append(f"Dateiname: {os.path.basename(pfad)}")
        zeilen.append(f"Aufloesung: {breite}x{hoehe}")
        zeilen.append(f"Frames /s: {fps}")
        zeilen.append(f"Modus : {'<<' if rueckwaerts else '>>'} {'PAUSE' if pause else 'LIVE'}")
        zeilen.append(f"Negativ  : {'ON' if negativ else 'OFF'}")
        zeilen.append(f"Dateigroesse: {os.path.getsize(pfad)//1024} KB")
        zeilen.append("")
        zeilen.append(f" ::SHA-256")
        hash_str = sha256_hash(pfad)
        zeilen.append(hash_str[:45])
        zeilen.append(hash_str[45:])
        zeilen.append(f" ::MD5")
        md5 = calculate_md5(pfad)
        zeilen.append(md5)

        # Durchschnittliche RGB Werte
        mean_colors = cv2.mean(bild)[:3] if not negativ else tuple(255 - x for x in cv2.mean(bild)[:3])
        zeilen.append(f"Avg. RGB: R={int(mean_colors[2])} G={int(mean_colors[1])} B={int(mean_colors[0])}")

        # Histogramm Grün
        hist = cv2.calcHist([bild], [1], None, [256], [0,256])
        hist = cv2.normalize(hist, hist).flatten()

        # EXIF Infos (max 15 Zeilen)
        exif_lines = exif_info(pfad)
        zeilen.append(":: 3XIF")
        zeilen.extend(exif_lines)

        # === Text auf meta_img schreiben ===
        y0 = 25
        dy = 20
        for i, text in enumerate(zeilen):
            if i < 50:  # Max Zeilenbegrenzung
                farbe = FARBE_TITLE if "::" in text else FARBE_VALUE

                cv2.putText(meta_img, text, (10, y0 + i * dy),
                            cv2.FONT_HERSHEY_PLAIN, 1, farbe, 1)

        # === Histogramm als kleine Grafik unten im meta_img (Grün Kanal) ===
        hist_h = 100
        hist_w = METADATEN_BREITE - 20
        hist_img = np.zeros((hist_h, hist_w, 3), dtype=np.uint8)

        for x in range(1, hist_w):
            y1 = int(hist_h - hist[int(x * 256 / hist_w)] * hist_h)
            y2 = hist_h
            farbe = FARBE_VALUE if y1 > 80 else FARBE_GRUEN if y1 > 90 else FARBE_ROT
            cv2.line(hist_img, (x-1, y1), (x, y2), farbe, 1)

        # Histogramm unten rechts einfügen
        start_y = hoehe - hist_h - 10
        if start_y >= 0:
            meta_img[start_y:start_y+hist_h, 10:10+hist_w] = hist_img

        # === Gesamtbild erstellen (frame + meta) ===
        gesamt = np.hstack((frame, meta_img))

        # === Steuerungslegende unten links im Video ===
        legende = [
            "(SPACE) Pause/Play",
            "(a)      Rückwärts",
            "(d)      Vorwärts",
            "(+)      FPS erhöhen",
            "(-)      FPS verringern",
            "(n)      Negativ umschalten",
            "(ESC)   Beenden"
            "-- shift000 --"
        ]
        for i, text in enumerate(legende):
            farbe = FARBE_TITLE if not negativ else FARBE_VALUE
            cv2.putText(gesamt, text, (10, hoehe - 140 + i * 20),
                        cv2.FONT_HERSHEY_PLAIN, 1, farbe, 1)

        cv2.imshow(NAME, gesamt)

        key = cv2.waitKey(int(1000 / fps)) & 0xFF

        # === STEUERUNG ===
        if key == 27:  # ESC
            break
        elif key == ord(' '):  # Pause/Play
            pause = not pause
        elif key == ord('a'):  # Rückwärts
            rueckwaerts = True
            pause = False
        elif key == ord('d'):  # Vorwärts
            rueckwaerts = False
            pause = False
        elif key == ord('+') or key == ord('='):  # FPS erhöhen
            fps = min(60, fps + 1)
        elif key == ord('-') or key == ord('_'):  # FPS senken
            fps = max(1, fps - 1)
        elif key == ord('n'):  # Negativ umschalten
            negativ = not negativ

        # === FRAME-WECHSEL ===
        if not pause:
            if rueckwaerts:
                index = (index - 1) % len(bilder)
            else:
                index = (index + 1) % len(bilder)

    cv2.destroyAllWindows()

def extract_jpegs_from_stream(stream_file_path, output_dir):
    # JPEG-Signaturen
    jpeg_start = b'\xff\xd8'  # Start Of Image (SOI)
    jpeg_end = b'\xff\xd9'    # End Of Image (EOI)

    with open(stream_file_path, 'rb') as f:
        data = f.read()

    pos = 0
    img_count = 0

    while True:
        start_idx = data.find(jpeg_start, pos)
        if start_idx == -1:
            break

        end_idx = data.find(jpeg_end, start_idx)
        if end_idx == -1:
            print(f"WARNUNG: Kein EOI für JPEG #{img_count + 1} gefunden. Abbruch.")
            break

        # Einschließlich der EOI-Signatur
        jpeg_data = data[start_idx:end_idx + 2]

        # Sicherstellen, dass das Ausgabeverzeichnis existiert
        os.makedirs(output_dir, exist_ok=True)

        output_path = os.path.join(output_dir, f'image_{img_count:03d}.jpg')
        with open(output_path, 'wb') as out_file:
            out_file.write(jpeg_data)

        print(f'Extrahiert: {output_path} ({len(jpeg_data)} Bytes)')

        img_count += 1
        pos = end_idx + 2

    print(f"\n[?] Extraktion abgeschlossen\n > {img_count} JPEG-Datei(en) gefunden")
    return img_count


input_stream_path = 'Datastream.dat'  # Pfad zur aus Wireshark exportierten Datei
output_folder = 'extrahierte_bilder'

answ = input(f"Viewer starten? [Y/n]\n > ")
if answ in ("y", "Y") or len(answ) == 0:
    init_image_viewer()
else:
    answ = input(f"Daten aus jpeg-Datenstrom {input_stream_path} extrahieren? [Y/n]\n > ")
    if answ in ("y", "Y") or len(answ) == 0:
        found = extract_jpegs_from_stream(input_stream_path, output_folder)
        if found > 0:
            answ = input("Viewer starten? [Y/n]\n > ")
            if answ in ("y", "Y") or len(answ) == 0:
                init_image_viewer()
exit()
