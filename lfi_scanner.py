import requests
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import argparse

# Argumente parsen
parser = argparse.ArgumentParser(description="LFI-Scanner mit optionaler div-Extraktion.")
parser.add_argument("-u", "--url", required=True, help="Basis-URL, z. B. http://10.10.122.37/?page=")
parser.add_argument("-w", "--wordlist", default="wordlist.txt", help="Pfad zur Wortliste (Standard: wordlist.txt)")
parser.add_argument("-t", "--threads", type=int, default=5, help="Anzahl der Threads (Standard: 5)")
parser.add_argument(
    "-d", "--div",
    help="Optional: Extrahiere nur Inhalt aus einem bestimmten <div>. Angabe z. B. class=mein-div oder id=mein-id."
)

args = parser.parse_args()

BASE_URL = args.url
WORDLIST_PATH = args.wordlist
MAX_THREADS = args.threads
EXTRACT_DIV_ONLY = args.div

url_or_ip = BASE_URL.split("://")[-1].split("/")[0]
LOGFILE = f"lfi_scan_results_{url_or_ip}.txt"
lock = threading.Lock()

def load_wordlist(path: str) -> list:
    """Lädt Pfade aus der Wortliste und ignoriert Kommentare und leere Zeilen."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
    except FileNotFoundError:
        print(f"[!] Fehler: Die Datei '{path}' wurde nicht gefunden.")
        return []

def fetch_page_content(url: str) -> str:
    """
    Sendet eine HTTP-Anfrage und extrahiert den Text:
    - Aus einem angegebenen <div> per class oder id (via --div),
    - Fallback: <body>, dann <html>, dann gesamter Text.
    """
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")

        if args.div:
            if "=" not in args.div:
                return "[Fehlerhafte --div-Angabe: bitte 'class=name' oder 'id=name' verwenden]"
            attr, value = args.div.split("=", 1)
            if attr == "class":
                div = soup.find("div", class_=value)
            elif attr == "id":
                div = soup.find("div", id=value)
            else:
                return "[Ungültiges Attribut in --div: nur 'class' oder 'id' erlaubt]"

            if div:
                return div.get_text(separator="\n", strip=True)
            # Fallback, falls kein entsprechender div gefunden wurde
            elif soup.body:
                return soup.body.get_text(separator="\n", strip=True)
            elif soup.html:
                return soup.html.get_text(separator="\n", strip=True)
            else:
                return soup.get_text(separator="\n", strip=True)
        else:
            if soup.body:
                return soup.body.get_text(separator="\n", strip=True)
            elif soup.html:
                return soup.html.get_text(separator="\n", strip=True)
            else:
                return soup.get_text(separator="\n", strip=True)

    except requests.RequestException as e:
        return f"[Fehler bei HTTP-Anfrage: {e}]"
        
def scan_path(path: str) -> str:
    """Führt einen Scan für einen einzelnen Pfad durch."""
    target_url = BASE_URL + path
    content = fetch_page_content(target_url)
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
            print(future.result())

if __name__ == "__main__":
    perform_lfi_scan()
