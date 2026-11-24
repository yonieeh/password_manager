#!/usr/bin/env bash
# run_experiments.sh: ataque por diccionario contra vaults de prueba con distintas
# configuraciones de Argon2id. Genera resultados/dict_attack.csv.
#
# Uso (desde la raíz del proyecto):
#   ./tools/run_experiments.sh            # 3 configuraciones, diccionario de 40 palabras
#   WORDS=200 ./tools/run_experiments.sh  # más palabras (más lento y más preciso)
#
# Variables opcionales:
#   VAULT_SRC   archivos de vault/entry  (por defecto: src/vault/entry.c src/vault/vault.c)
#   EXTRA_INC   include extra            (por defecto: nada)
#   WORDS       tamaño del diccionario   (por defecto: 40)
#
# Cada configuración compila storage.c con -DSTORAGE_KDF_OPSLIMIT / MEMLIMIT distintos,
# crea una vault de prueba con ese costo y la ataca. La master correcta va AL FINAL del
# diccionario, así el ataque recorre todas las palabras (el caso "no hay suerte").
set -euo pipefail

cd "$(dirname "$0")/.."

VAULT_SRC="${VAULT_SRC:-src/vault/entry.c src/vault/vault.c}"
EXTRA_INC="${EXTRA_INC:-}"
WORDS="${WORDS:-40}"
MASTER="la-master-correcta-2026"

OUT=resultados
BIN=build/exp
mkdir -p "$OUT" "$BIN"

# Diccionario de prueba: palabras inventadas + la master correcta al final.
DICT="$BIN/diccionario.txt"
{ for i in $(seq 1 $((WORDS - 1))); do echo "palabra-incorrecta-$i"; done; echo "$MASTER"; } > "$DICT"

# nombre : ops : memoria en bytes
CONFIGS=(
  "debil_1x8MiB:1:8388608"
  "liviana_2x64MiB:2:67108864"
  "moderada_3x256MiB:3:268435456"
  "fuerte_4x512MiB:4:536870912"
)

CSV="$OUT/dict_attack.csv"
echo "config,ops,mem_mib,found,position,tried,seconds,guesses_per_s" > "$CSV"

for cfg in "${CONFIGS[@]}"; do
  IFS=: read -r name ops mem <<< "$cfg"
  echo "== $name (ops=$ops, mem=$((mem / 1048576)) MiB)"

  # shellcheck disable=SC2086
  for tool in make_test_vault dict_attack; do
    gcc -std=gnu11 -Wall -Wextra -O2 -Isrc $EXTRA_INC \
      -DSTORAGE_KDF_OPSLIMIT="$ops"ULL -DSTORAGE_KDF_MEMLIMIT="$mem"ULL \
      "tools/$tool.c" src/storage/storage.c $VAULT_SRC -lsodium -o "$BIN/${tool}_$name"
  done

  VAULT="$BIN/vault_$name.bin"
  rm -f "$VAULT"
  "$BIN/make_test_vault_$name" "$VAULT" "$MASTER"

  res=$("$BIN/dict_attack_$name" "$VAULT" "$DICT")
  echo "   found,position,tried,seconds,guesses_per_s = $res"
  echo "$name,$ops,$((mem / 1048576)),$res" >> "$CSV"

  rm -f "$VAULT"
done

echo
echo "Resultados en $CSV"