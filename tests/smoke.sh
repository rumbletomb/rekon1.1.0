#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

PROJECT_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
TEST_ROOT=$(mktemp -d)
trap 'rm -rf -- "$TEST_ROOT"' EXIT

first_run_dir() {
  find "$1" -mindepth 1 -maxdepth 1 -type d -print -quit
}

bash -n "$PROJECT_ROOT/rekon.sh"
bash "$PROJECT_ROOT/rekon.sh" --self-test

# Perfil balanced completo: no instala, usa TCP top 1000 y UDP top 50.
bash "$PROJECT_ROOT/rekon.sh" \
  --target lab.example.com \
  --wordlists "$PROJECT_ROOT/tests/fixtures/wordlists" \
  --profile balanced \
  --output "$TEST_ROOT/balanced" \
  --dry-run \
  --no-install \
  --sudo-scans \
  --non-interactive \
  --accept-authorized-use \
  --no-color >/dev/null

BALANCED_RUN=$(first_run_dir "$TEST_ROOT/balanced")
[[ -n $BALANCED_RUN ]]
[[ -s $BALANCED_RUN/report/REKON-report.md ]]
[[ -s $BALANCED_RUN/report/summary.json ]]
[[ -s $BALANCED_RUN/SHA256SUMS ]]
[[ -s $BALANCED_RUN/00-meta/scan-policy.tsv ]]
[[ -s $BALANCED_RUN/00-meta/requirements-tools.tsv ]]
[[ $(wc -l <"$BALANCED_RUN/00-meta/selected-wordlists.tsv") -eq 7 ]]

grep -Fq 'nmap ' "$BALANCED_RUN/logs/commands.tsv"
grep -Fq -- '--top-ports 1000' "$BALANCED_RUN/logs/commands.tsv"
grep -Fq -- '-sU -sV --version-light' "$BALANCED_RUN/logs/commands.tsv"
grep -Fq -- '--top-ports 50' "$BALANCED_RUN/logs/commands.tsv"
grep -Eq $'^resolvers\t[^-]' "$BALANCED_RUN/00-meta/selected-wordlists.tsv"
grep -Fq 'ffuf ' "$BALANCED_RUN/logs/commands.tsv"
grep -Fq 'nuclei ' "$BALANCED_RUN/logs/commands.tsv"
grep -Fq -- '-exclude-tags' "$BALANCED_RUN/logs/commands.tsv"
grep -Fq $'report\tOK' "$BALANCED_RUN/00-meta/modules.tsv"
if grep -Fq 'apt-get install' "$BALANCED_RUN/logs/commands.tsv"; then
  printf 'FAIL: --no-install planifico APT\n' >&2
  exit 1
fi

# El instalador puede auditarse por completo sin efectuar cambios.
bash "$PROJECT_ROOT/rekon.sh" \
  --target 192.0.2.10 \
  --wordlists "$PROJECT_ROOT/tests/fixtures/wordlists" \
  --profile balanced \
  --output "$TEST_ROOT/install-plan" \
  --install-deps \
  --no-sudo-scans \
  --only report \
  --dry-run \
  --non-interactive \
  --accept-authorized-use \
  --no-color >/dev/null

INSTALL_RUN=$(first_run_dir "$TEST_ROOT/install-plan")
grep -Fq 'apt-get update' "$INSTALL_RUN/logs/commands.tsv"
grep -Fq 'go install github.com/projectdiscovery/pdtm' "$INSTALL_RUN/logs/commands.tsv"
grep -Fq 'Instalacion ProjectDiscovery con PDTM' "$INSTALL_RUN/logs/commands.tsv"
grep -Fq 'pipx install arjun' "$INSTALL_RUN/logs/commands.tsv"

# Perfil deep, motores complementarios y rutas con espacios.
mkdir -p "$TEST_ROOT/deep case"
cp -R "$PROJECT_ROOT/tests/fixtures/wordlists" "$TEST_ROOT/deep case/word lists"
bash "$PROJECT_ROOT/rekon.sh" \
  --target lab.example.com \
  --wordlists "$TEST_ROOT/deep case/word lists" \
  --profile deep \
  --output "$TEST_ROOT/deep case/output dir" \
  --dry-run \
  --no-install \
  --sudo-scans \
  --non-interactive \
  --accept-authorized-use \
  --no-color >/dev/null

DEEP_RUN=$(first_run_dir "$TEST_ROOT/deep case/output dir")
grep -Fq -- '-p-' "$DEEP_RUN/logs/commands.tsv"
grep -Fq -- '--top-ports 200' "$DEEP_RUN/logs/commands.tsv"
grep -Fq 'Crawling complementario con Hakrawler' "$DEEP_RUN/logs/commands.tsv"
grep -Fq 'Recursion web profunda con Feroxbuster' "$DEEP_RUN/logs/commands.tsv"
grep -Fq 'Contraste de virtual hosts con Gobuster' "$DEEP_RUN/logs/commands.tsv"
grep -Fq 'Descubrimiento de parametros GET con Arjun' "$DEEP_RUN/logs/commands.tsv"
grep -Fq ' < ' "$DEEP_RUN/logs/commands.tsv"

# Sin autorización raw se usa TCP connect y no se planifica UDP, incluso como root.
bash "$PROJECT_ROOT/rekon.sh" \
  --target 192.0.2.20 \
  --wordlists "$PROJECT_ROOT/tests/fixtures/wordlists" \
  --profile balanced \
  --tcp-ports 80,443 \
  --udp-ports 53 \
  --output "$TEST_ROOT/unprivileged" \
  --only ports,report \
  --dry-run \
  --no-install \
  --no-sudo-scans \
  --non-interactive \
  --accept-authorized-use \
  --no-color >/dev/null

UNPRIV_RUN=$(first_run_dir "$TEST_ROOT/unprivileged")
grep -Fq -- '-sT' "$UNPRIV_RUN/logs/commands.tsv"
if grep -Fq -- '-sU' "$UNPRIV_RUN/logs/commands.tsv"; then
  printf 'FAIL: se planifico UDP sin privilegios\n' >&2
  exit 1
fi

if bash "$PROJECT_ROOT/rekon.sh" --tcp-ports 70000 --self-test >/dev/null 2>&1; then
  printf 'FAIL: se acepto un puerto fuera de rango\n' >&2
  exit 1
fi

printf 'Smoke test: OK\n'
