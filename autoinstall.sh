#!/bin/bash

# Hauptordner-Name
main_folder="Penetration-Testing-Toolbox"

# Erstellen der Ordnerstruktur
mkdir -p "$main_folder"/{Information_Gathering/{DNS,Network_Scanning,OSINT,Web_Scanning,Wireless},Vulnerability_Assessment/{Exploit_Scanners,Web_Vulnerability_Scanners,Configuration_Checkers},Exploitation/{Exploit_Frameworks,Web_Exploits,Network_Exploits,Privilege_Escalation,Payloads},Post_Exploitation/{Data_Exfiltration,Lateral_Movement,Persistence,Rootkits,Cleanup},Password_Attacks/{Brute_Force,Wordlists,Hash_Cracking},Social_Engineering/{Phishing_Tools,Email_Templates,Payload_Delivery},Wireless_Attacks/{WiFi_Cracking,Bluetooth,RFID},Web_Application/{Web_Proxies,CMS_Tools,API_Tools,Web_Exploits},Mobile_Testing/{Android,iOS,Emulator},Reverse_Engineering/{Binary_Analysis,Disassemblers,Decompilers,Malware_Analysis},Physical_Attacks/{RFID,Lockpicking,USB_Attacks},Documentation/{Reporting,Templates,Notes}}

# Erstellen der Datei info.txt mit den Erklärungen
cat <<EOL > "$main_folder/info.txt"
Ordnerstruktur im Detail:

Information_Gathering: Tools für die Sammlung öffentlicher Informationen (z. B. Reconnaissance-Tools für Netzwerke, DNS, OSINT).
Vulnerability_Assessment: Tools zum Identifizieren von Schwachstellen (Scans auf Schwachstellen, Sicherheitsprüfer).
Exploitation: Exploit-Frameworks (z. B. Metasploit), Privilegieneskalation und Netzwerk- sowie Web-Exploits.
Post_Exploitation: Tools und Skripte für die Aktivitäten nach erfolgreichem Exploit (Datenextraktion, lateral movement, Rootkits).
Password_Attacks: Brute-Force-Tools und Listen (z. B. für Hash-Cracking, Wortlisten für Passwort-Angriffe).
Social_Engineering: Werkzeuge und Templates für Phishing-Angriffe und die Zustellung von Payloads.
Wireless_Attacks: Tools für Angriffe auf kabellose Verbindungen (WLAN-Cracking, Bluetooth, RFID).
Web_Application: Proxys, spezifische CMS-Tools und Web-Exploits für die Penetration von Webanwendungen.
Mobile_Testing: Spezifische Tools für das Testen mobiler Apps und Emulatoren.
Reverse_Engineering: Tools für Binäranalyse, Disassembler und Malware-Analyse.
Physical_Attacks: Werkzeuge für physische Sicherheitsüberprüfungen (RFID, Lockpicking, USB-Angriffe).
Documentation: Ordner für Berichterstellung, Templates und allgemeine Notizen.
EOL

echo "Ordnerstruktur und info.txt erfolgreich erstellt unter $main_folder"
