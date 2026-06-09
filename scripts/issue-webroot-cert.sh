#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/issue-webroot-cert.sh --email admin@pxxl.app --domain example.com [--domain www.example.com]
  scripts/issue-webroot-cert.sh --email admin@pxxl.app --domains-file /tmp/domains.txt

Issues/renews a single SAN certificate using the proxy-served HTTP-01 webroot:
  /data/acme-challenges

The script writes env lines into .env so the edge container serves the trusted cert:
  PXXL_STATIC_LOCAL_CERT=/data/certs/<first-domain>-fullchain.pem
  PXXL_STATIC_LOCAL_KEY=/data/certs/<first-domain>-privkey.pem
USAGE
}

email=""
domains_file=""
domains=()

while [ "$#" -gt 0 ]; do
  case "$1" in
    --email)
      email="${2:-}"
      shift 2
      ;;
    --domain)
      domains+=("${2:-}")
      shift 2
      ;;
    --domains-file)
      domains_file="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

[ -n "$email" ] || { echo "--email is required" >&2; exit 2; }

if [ -n "$domains_file" ]; then
  [ -f "$domains_file" ] || { echo "domains file not found: $domains_file" >&2; exit 2; }
  while IFS= read -r domain; do
    domain="${domain%%#*}"
    domain="$(printf '%s' "$domain" | tr '[:upper:]' '[:lower:]' | xargs)"
    [ -n "$domain" ] && domains+=("$domain")
  done < "$domains_file"
fi

unique_domains=()
for domain in "${domains[@]}"; do
  domain="$(printf '%s' "$domain" | tr '[:upper:]' '[:lower:]' | xargs)"
  [ -n "$domain" ] || continue
  case "$domain" in
    *'*'*|localhost|*.local|*.test) continue ;;
  esac
  seen=false
  for existing in "${unique_domains[@]}"; do
    [ "$existing" = "$domain" ] && seen=true && break
  done
  [ "$seen" = false ] && unique_domains+=("$domain")
done

[ "${#unique_domains[@]}" -gt 0 ] || { echo "at least one valid --domain is required" >&2; exit 2; }
[ "${#unique_domains[@]}" -le 100 ] || { echo "Let's Encrypt allows at most 100 names per certificate; split the list" >&2; exit 2; }

cd "$(dirname "$0")/.."
mkdir -p data/acme-challenges data/letsencrypt data/certs

if ! command -v certbot >/dev/null 2>&1; then
  echo "certbot is required. Install it first, then rerun this script." >&2
  exit 1
fi

cert_name="${unique_domains[0]}"
args=(certonly --webroot -w "$PWD/data/acme-challenges" --config-dir "$PWD/data/letsencrypt" --work-dir "$PWD/data/letsencrypt-work" --logs-dir "$PWD/data/letsencrypt-logs" --cert-name "$cert_name" --agree-tos --non-interactive --email "$email" --keep-until-expiring)
for domain in "${unique_domains[@]}"; do
  args+=(-d "$domain")
done

certbot "${args[@]}"

host_cert_path="$PWD/data/certs/$cert_name-fullchain.pem"
host_key_path="$PWD/data/certs/$cert_name-privkey.pem"
cp -L "$PWD/data/letsencrypt/live/$cert_name/fullchain.pem" "$host_cert_path"
cp -L "$PWD/data/letsencrypt/live/$cert_name/privkey.pem" "$host_key_path"
chmod 0644 "$host_cert_path" "$host_key_path"

cert_path="/data/certs/$cert_name-fullchain.pem"
key_path="/data/certs/$cert_name-privkey.pem"

touch .env
tmp_env="$(mktemp)"
grep -v -E '^(PXXL_STATIC_LOCAL_CERT|PXXL_STATIC_LOCAL_KEY|PXXL_ACME_CHALLENGE_DIR)=' .env > "$tmp_env" || true
{
  printf 'PXXL_ACME_CHALLENGE_DIR=/data/acme-challenges\n'
  printf 'PXXL_STATIC_LOCAL_CERT=%s\n' "$cert_path"
  printf 'PXXL_STATIC_LOCAL_KEY=%s\n' "$key_path"
} >> "$tmp_env"
mv "$tmp_env" .env

echo "Certificate ready for ${unique_domains[*]}"
echo "Restart/redeploy the proxy edge so it loads $cert_path"
