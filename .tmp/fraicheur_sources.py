"""La fraicheur d'une source : la date de son dernier article publie, pas celle de nos envois."""
from pathlib import Path

VEILLE = Path(r"D:\Security Code GitHub\Sec_Daily_report-\veille.py")
texte = VEILLE.read_text(encoding="utf-8")

# 1. Le magasin, a cote des autres etats de source.
ancre = "SOURCE_RESULTS: dict[str, tuple[bool, str | None, int]] = {}"
assert ancre in texte, "SOURCE_RESULTS introuvable"
texte = texte.replace(ancre, ancre + """

#: Date du plus recent article *publie* par chaque flux, meme quand ses articles ne sont pas
#: retenus. C'est ce que mesure le bandeau des sources silencieuses : la sante du flux, pas
#: notre propre filtrage.
SOURCE_FRAICHEUR: dict[str, str] = {}


def _noter_fraicheur(nom: str, entrees) -> None:
    \"\"\"Retient la date du plus recent article du flux, sans le moindre filtrage.\"\"\"
    recentes = []
    for entree in entrees:
        for cle in ("published_parsed", "updated_parsed"):
            valeur = entree.get(cle)
            if valeur:
                try:
                    recentes.append(datetime(*valeur[:6], tzinfo=timezone.utc))
                except (TypeError, ValueError):
                    pass
                break
    if recentes:
        SOURCE_FRAICHEUR[nom] = max(recentes).date().isoformat()""", 1)

# 2. L'alimenter a chaque flux lu.
ancre2 = """    try:
        feed = feedparser.parse(response.content)
    except Exception as exc:  # noqa: BLE001 - un flux exotique ne doit pas tuer la source
        log.warning("%s: unreadable feed (%s)", source["name"], exc)
        return [], f"{source['name']}: unreadable feed ({type(exc).__name__})"
"""
assert ancre2 in texte, "bloc de parsing introuvable"
texte = texte.replace(ancre2, ancre2 + """
    _noter_fraicheur(source["name"], feed.entries)
""", 1)

# 3. Ecrire cette date plutot que l'heure du run.
avant3 = """                    (nom, url, categorie, poids, maintenant,
                     maintenant if nb else dernier_article,"""
apres3 = """                    (nom, url, categorie, poids, maintenant,
                     SOURCE_FRAICHEUR.get(nom) or (maintenant if nb else dernier_article),"""
assert avant3 in texte, "ecriture de dernier_article introuvable"
texte = texte.replace(avant3, apres3, 1)

# 4. Lire cette date pour le bandeau, avec repli sur la table des articles.
avant4 = """    try:
        rows = list(conn.execute("SELECT source, MAX(vu_le) FROM articles GROUP BY source"))
    except sqlite3.Error:
        return []"""
apres4 = """    try:
        # La date du dernier article *publie* par le flux, quand elle est connue ; la table des
        # articles ne sert plus que de repli pour les sources jamais vues depuis la migration.
        rows = list(conn.execute(
            "SELECT nom, dernier_article FROM sources WHERE dernier_article IS NOT NULL"))
        connues_en_base = {str(nom) for nom, _ in rows}
        rows += [ligne for ligne in conn.execute(
            "SELECT source, MAX(vu_le) FROM articles GROUP BY source")
            if str(ligne[0]) not in connues_en_base]
    except sqlite3.Error:
        return []"""
assert avant4 in texte, "lecture des sources silencieuses introuvable"
texte = texte.replace(avant4, apres4, 1)

VEILLE.write_text(texte, encoding="utf-8")
print("veille.py : fraicheur des flux branchee")
