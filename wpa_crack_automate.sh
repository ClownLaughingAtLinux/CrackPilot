#!/usr/bin/env bash
# wpa_crack_automate.sh
# Parrot OS - automatisiert: prüft pcap/cap, extrahiert 22000-Hash, startet hashcat oder aircrack-ng
# Nur für legale Pentests / eigene Netze oder mit Zustimmung des Eigentümers.

set -euo pipefail
IFS=$'\n\t'

PROGNAME=$(basename "$0")
WORKDIR=$(pwd)/wpa_crack_workdir
OUTDIR="$WORKDIR/results"
TMPHASH="$WORKDIR/handshakes.22000"

usage() {
  cat <<EOF
Usage: $PROGNAME -i capture.pcap -w wordlist.txt [-m hashcat|aircrack] [-b BSSID] [-s SSID]

  -i <file>      : Eingangs-Capture (.pcap, .pcapng, .cap)
  -w <file>      : Wortliste (wordlist)
  -m <mode>      : "hashcat" (default) oder "aircrack"
  -b <BSSID>     : optional, BSSID des AP (z.B. AA:BB:CC:DD:EE:FF) für aircrack
  -s <SSID>      : optional, SSID (nur informative Zwecke)
  -h             : diese Hilfe

Example:
  $PROGNAME -i capture.pcap -w /usr/share/wordlists/rockyou.txt -m hashcat
EOF
  exit 1
}

# Defaults
MODE="hashcat"
BSSID=""
SSID=""
CAP=""

# Parse args
while getopts ":i:w:m:b:s:h" opt; do
  case $opt in
    i) CAP="$OPTARG" ;;
    w) WORDLIST="$OPTARG" ;;
    m) MODE="$OPTARG" ;;
    b) BSSID="$OPTARG" ;;
    s) SSID="$OPTARG" ;;
    h|*) usage ;;
  esac
done

if [[ -z "${CAP:-}" || -z "${WORDLIST:-}" ]]; then
  usage
fi

# Basic checks
command_exists() { command -v "$1" >/dev/null 2>&1; }

echo "=> Workspace: $WORKDIR"
mkdir -p "$WORKDIR" "$OUTDIR"

if [[ ! -f "$CAP" ]]; then
  echo "ERROR: Capture-Datei '$CAP' nicht gefunden." >&2
  exit 2
fi
if [[ ! -f "$WORDLIST" ]]; then
  echo "ERROR: Wortliste '$WORDLIST' nicht gefunden." >&2
  exit 2
fi

# Ensure required tools
NEEDED=(hcxpcapngtool)
if [[ "$MODE" == "hashcat" ]]; then
  NEEDED+=(hashcat)
else
  NEEDED+=(aircrack-ng)
fi

MISSING=()
for t in "${NEEDED[@]}"; do
  if ! command_exists "$t"; then
    MISSING+=("$t")
  fi
done

if (( ${#MISSING[@]} )); then
  echo "Fehlende Tools: ${MISSING[*]}"
  echo "Möchtest du versuchen, sie jetzt zu installieren? (apt)"
  read -r -p "[y/N] " ans
  if [[ "$ans" =~ ^[Yy]$ ]]; then
    sudo apt update
    for t in "${MISSING[@]}"; do
      sudo apt install -y "$t" || { echo "Installation von $t fehlgeschlagen — bitte manuell installieren."; exit 3; }
    done
  else
    echo "Abbruch: fehlende Abhängigkeiten." >&2
    exit 4
  fi
fi

# Step 1: Extract handshake -> 22000 (hashcat mode format)
echo "=> Extrahiere handshakes aus '$CAP' nach $TMPHASH ..."
rm -f "$TMPHASH"
# hcxpcapngtool funktioniert mit .pcap/.pcapng/.cap -> erzeugt 22000
if ! hcxpcapngtool -o "$TMPHASH" "$CAP" >/dev/null 2>&1; then
  echo "Warnung: hcxpcapngtool gab einen Fehler zurück oder fand nichts."
fi

if [[ ! -s "$TMPHASH" ]]; then
  echo "Hinweis: Es wurde kein 22000-Hash extrahiert (leere Datei)."
  # Wenn aircrack-Modus: wir versuchen trotzdem direkt mit aircrack
  if [[ "$MODE" == "aircrack" ]]; then
    echo "Weiter mit aircrack-ng (direkt auf der Capture-Datei)."
  else
    echo "Wenn kein 22000-Hash vorhanden ist, funktioniert hashcat nicht. Du kannst versuchen, mit aircrack-ng zu prüfen."
  fi
fi

timestamp() { date +"%Y%m%d_%H%M%S"; }
LOG="$OUTDIR/run_$(timestamp).log"

if [[ "$MODE" == "hashcat" ]]; then
  if [[ ! -s "$TMPHASH" ]]; then
    echo "FEHLER: Kein gültiger 22000-Hash gefunden — Abbruch." | tee -a "$LOG"
    echo "Tipp: Stelle sicher, dass die Capture-Datei einen vollständigen 4-way EAPOL-Handshake oder PMKID enthält." | tee -a "$LOG"
    exit 6
  fi
  echo "=> Starte hashcat (Modus 22000) ..."
  # Optional: user kann zusätzliche hashcat-Optionen setzen via ENV HASHCAT_OPTS
  HASHCAT_OPTS="${HASHCAT_OPTS:---status --status-timer=10}"
  echo "hashcat -m 22000 $TMPHASH $WORDLIST $HASHCAT_OPTS" | tee -a "$LOG"
  hashcat -m 22000 "$TMPHASH" "$WORDLIST" $HASHCAT_OPTS 2>&1 | tee -a "$LOG"
  echo "=> Hashcat beendet. Prüfe Ergebnisse mit 'hashcat --show'."
  echo "Zeige gefundene Passwörter (falls vorhanden):" | tee -a "$LOG"
  hashcat --show "$TMPHASH" 2>&1 | tee -a "$LOG" || true

  # Kopiere hash und log in results
  cp -v "$TMPHASH" "$OUTDIR/" 2>/dev/null || true
  mv -v "$LOG" "$OUTDIR/" 2>/dev/null || true

else
  # aircrack-ng flow
  echo "=> Starte aircrack-ng gegen '$CAP' ..."
  ARBCMD=(aircrack-ng -w "$WORDLIST")
  if [[ -n "$BSSID" ]]; then
    ARBCMD+=(-b "$BSSID")
  fi
  ARBCMD+=("$CAP")
  echo "${ARBCMD[*]}" | tee -a "$LOG"
  "${ARBCMD[@]}" 2>&1 | tee -a "$LOG"
  echo "=> aircrack-ng beendet. Log liegt in $LOG"
  mv -v "$LOG" "$OUTDIR/" 2>/dev/null || true
fi

echo "=> Fertig. Ergebnisse (Logs/Hashes) in: $OUTDIR"
echo "Hinweis: WPA3/SAE Handshakes werden von diesem Workflow NICHT zuverlässig geknackt."
exit 0

