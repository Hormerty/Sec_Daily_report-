#!/usr/bin/env bash
# Sauvegarde l'état sur la branche « data » : un seul commit orphelin, poussé en --force.
# L'historique ne grossit donc pas, malgré le stats.db binaire.
# (Ne pas protéger cette branche, sinon le force-push sera refusé.)
set -euo pipefail
BRANCHE="${ETAT_BRANCHE:-data}"
FICHIERS=(seen.json stats.db kev_cache.json alertes_envoyees.json metasploit_cache.json)
REMOTE="${ETAT_REMOTE:-}"
if [ -z "$REMOTE" ]; then
  : "${GH_TOKEN:?GH_TOKEN manquant}"
  REMOTE="https://x-access-token:${GH_TOKEN}@${GITHUB_SERVER_URL#https://}/${GITHUB_REPOSITORY}.git"
fi

SRC="$PWD"
tmp="$(mktemp -d)"
n=0
for f in "${FICHIERS[@]}"; do
  if [ -f "$SRC/$f" ]; then
    cp "$SRC/$f" "$tmp/$f"
    n=$((n + 1))
  fi
done
if [ "$n" -eq 0 ]; then
  echo "Aucun fichier d'état à sauvegarder."
  exit 0
fi

cd "$tmp"
git init -q -b "$BRANCHE"
git config user.name "noursecbot"
git config user.email "noursecbot@users.noreply.github.com"
git add -A
git commit -q -m "état $(date -u +%F)"

for i in 1 2 3; do
  if git push -q --force "$REMOTE" "$BRANCHE"; then
    echo "État sauvegardé sur '$BRANCHE' ($n fichier(s))."
    exit 0
  fi
  echo "Push échoué, tentative $i/3"
  sleep $((i * 5))
done
exit 1
