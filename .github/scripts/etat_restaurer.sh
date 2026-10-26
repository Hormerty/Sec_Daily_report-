#!/usr/bin/env bash
# Restaure seen.json, stats.db et kev_cache.json depuis la branche « data ».
# Sécurité : si la branche existe mais ne peut pas être lue, on s'arrête (code 1)
# plutôt que de repartir d'une base vide qui écraserait l'historique à la sauvegarde.
set -euo pipefail
BRANCHE="${ETAT_BRANCHE:-data}"
FICHIERS=(seen.json stats.db kev_cache.json alertes_envoyees.json)

set +e
git ls-remote --exit-code --heads origin "$BRANCHE" >/dev/null 2>&1
rc=$?
set -e
case "$rc" in
  0) ;;
  2)
    echo "Branche '$BRANCHE' absente : premier run, on utilise les fichiers du dépôt s'il y en a."
    exit 0
    ;;
  *)
    echo "::error::Lecture de la branche '$BRANCHE' impossible (git ls-remote, code $rc) : arrêt pour ne pas écraser l'état."
    exit 1
    ;;
esac

git fetch --quiet --depth=1 origin "$BRANCHE"
for f in "${FICHIERS[@]}"; do
  if git cat-file -e "FETCH_HEAD:$f" 2>/dev/null; then
    git cat-file blob "FETCH_HEAD:$f" > "$f"
    echo "Restauré : $f"
  fi
done
