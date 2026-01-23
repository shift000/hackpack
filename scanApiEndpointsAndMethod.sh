#!/usr/bin/env bash

usage() {
  echo "Usage: $0 -u <base_url> -f <endpoint_file> [-t <bearer_token>]"
  echo
  echo "Parameter:"
  echo "  -u  Base URL (z. B. https://example.com)"
  echo "  -f  Datei mit Endpunkten (ein Endpunkt pro Zeile)"
  echo "  -t  Optional: Bearer Token"
  echo "  -h  Hilfe anzeigen"
  exit 0
}

while getopts ":u:f:t:h" opt; do
  case $opt in
    u) BASE_URL="$OPTARG" ;;
    f) ENDPOINT_FILE="$OPTARG" ;;
    t) TOKEN="$OPTARG" ;;
    h) usage ;;
    *) usage ;;
  esac
done

if [[ -z "$BASE_URL" || -z "$ENDPOINT_FILE" ]]; then
  usage
fi

if [[ ! -f "$ENDPOINT_FILE" ]]; then
  echo "Fehler: Datei $ENDPOINT_FILE nicht gefunden"
  exit 1
fi

METHODS=("GET" "POST" "PUT" "DELETE" "OPTIONS")
AUTH_HEADER=()
[[ -n "$TOKEN" ]] && AUTH_HEADER=(-H "Authorization: Bearer $TOKEN")

TOTAL_ENDPOINTS=$(grep -cve '^\s*$' "$ENDPOINT_FILE")
SCANNED=0

echo "================================================="
echo "API Endpoint Scan"
echo "Base URL        : $BASE_URL"
echo "Endpoint-Datei  : $ENDPOINT_FILE"
echo "Anzahl Endpunkte: $TOTAL_ENDPOINTS"
echo "Methoden        : ${METHODS[*]}"
[[ -n "$TOKEN" ]] && echo "Auth            : Bearer Token gesetzt"
echo "================================================="

printf "GET POST PUT DEL OPTIONS"
while IFS= read -r endpoint || [[ -n "$endpoint" ]]; do
  [[ -z "$endpoint" ]] && continue
  ((SCANNED++))
  REMAINING=$((TOTAL_ENDPOINTS - SCANNED))

  echo
  #echo "[$SCANNED/$TOTAL_ENDPOINTS] $endpoint (übrig: $REMAINING)"

  for method in "${METHODS[@]}"; do
    response=$(curl -s -X "$method" "${AUTH_HEADER[@]}" \
      -w "\n__HTTP_CODE__:%{http_code}" \
      "$BASE_URL$endpoint")

    body=$(echo "$response" | sed '/__HTTP_CODE__/d')
    code=$(echo "$response" | sed -n 's/.*__HTTP_CODE__://p')

    #echo "  $method"
    #echo "  +--------+"
    printf " $code" "$method"
    #echo "  +--------+"

    #if [[ -n "$body" ]]; then
    #  echo "$body" | sed 's/^/    /'
    #else
    #  echo "    <leerer Response-Body>"
    #fi
  done
  printf "     $endpoint"
done < "$ENDPOINT_FILE"

echo
echo "================================================="
echo "Scan abgeschlossen: $SCANNED Endpunkte geprüft"
echo "================================================="
