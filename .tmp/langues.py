"""A : etiqueter la langue des titres non anglais. C : ecarter les ecritures non latines."""
from pathlib import Path

VEILLE = Path(r"D:\Security Code GitHub\Sec_Daily_report-\veille.py")
texte = VEILLE.read_text(encoding="utf-8")

# --- 1. La detection, a cote des tables de traduction --------------------------------
ancre = "def is_relevant(text: str) -> bool:"
assert ancre in texte
detection = '''def detecter_langue(titre: str) -> str | None:
    """Langue probable d'un titre, ou None s'il est anglais ou indécidable.

    Deux signaux, dans cet ordre : l'écriture (grec, japonais, chinois, coréen, cyrillique,
    arabe, hébreu) qui ne laisse aucun doute, puis les mots-outils et les diacritiques pour les
    langues latines. Aucun dictionnaire complet : il s'agit de dire au lecteur qu'un titre est
    étranger, pas de le traduire.
    """
    for code, motif in _ECRITURES:
        if motif.search(titre):
            return code
    minuscule = titre.lower()
    for code, motif in _DIACRITIQUES:
        if motif.search(minuscule):
            return code
    mots = re.findall(r"[a-zà-ÿ]+", minuscule)
    if len(mots) < 3:
        return None
    scores = {code: sum(1 for mot in mots if mot in locutions)
              for code, locutions in _LANGUE_MOTS.items()}
    meilleur = max(scores, key=lambda code: scores[code])
    return meilleur if scores[meilleur] >= 2 else None


'''
texte = texte.replace(ancre, detection + ancre, 1)

# --- 2. Les tables de signaux --------------------------------------------------------
ancre2 = "def detecter_langue(titre: str) -> str | None:"
tables = '''_ECRITURES = (
    ("el", re.compile(r"[\\u0370-\\u03ff\\u1f00-\\u1fff]")),
    ("ja", re.compile(r"[\\u3040-\\u30ff]")),
    ("zh", re.compile(r"[\\u4e00-\\u9fff]")),
    ("ko", re.compile(r"[\\uac00-\\ud7af]")),
    ("ru", re.compile(r"[\\u0400-\\u04ff]")),
    ("ar", re.compile(r"[\\u0600-\\u06ff]")),
    ("he", re.compile(r"[\\u0590-\\u05ff]")),
)

_DIACRITIQUES = (
    ("pt", re.compile(r"[ãõ]")),
    ("es", re.compile(r"[ñ¿¡]")),
    ("de", re.compile(r"[ßäöü]")),
    ("fr", re.compile(r"[èêàçœ]")),
    ("it", re.compile(r"[ìòù]")),
)

#: Mots-outils discriminants. Volontairement peu nombreux et sans terme ambigu avec l'anglais.
_LANGUE_MOTS = {
    "fr": frozenset({"les", "des", "une", "aux", "avec", "pour", "dans", "sur", "est"}),
    "es": frozenset({"los", "las", "una", "del", "para", "por", "que", "con"}),
    "pt": frozenset({"uma", "não", "com", "para", "dos", "das", "pelo"}),
    "it": frozenset({"gli", "una", "della", "con", "per", "che", "dei"}),
    "de": frozenset({"der", "die", "das", "und", "mit", "für", "eine", "nicht"}),
    "nl": frozenset({"het", "een", "van", "met", "voor", "niet", "dat"}),
    "sl": frozenset({"tudi", "ter", "pri", "zaradi", "lahko"}),
}


'''
texte = texte.replace(ancre2, tables + ancre2, 1)

# --- 3. Le compteur des titres ecartes -----------------------------------------------
ancre3 = "SOURCE_FRAICHEUR: dict[str, str] = {}"
assert ancre3 in texte
texte = texte.replace(ancre3, ancre3 + '''

#: Titres écartés faute d'écriture lisible, par source. Comptés, jamais tus.
LANGUES_ECARTEES: dict[str, int] = {}''', 1)

# --- 4. L'ecartement, dans la collecte ------------------------------------------------
ancre4 = "        text = _entry_text(entry)"
assert ancre4 in texte
ecartement = '''        # Une écriture que nous ne pouvons ni traduire ni interpréter n'apporte rien au
        # lecteur : elle est écartée des flux multilingues, et comptée.
        if source.get("multilingue"):
            langue = detecter_langue(title)
            if langue in ("ja", "zh", "ko", "ru", "el", "ar", "he"):
                LANGUES_ECARTEES[source["name"]] = LANGUES_ECARTEES.get(source["name"], 0) + 1
                continue
'''
texte = texte.replace(ancre4, ecartement + ancre4, 1)

# --- 5. L'etiquette dans le rendu ----------------------------------------------------
ancre5 = "f'{_lien_html(a.link, a.title)}{metr} '"
assert ancre5 in texte
texte = texte.replace(ancre5, "f'{_lien_html(a.link, a.title)}{_etiquette_langue(a.title)}{metr} '", 1)

ancre6 = "def _lien_html(url: str, texte: str) -> str:"
etiquette = '''def _etiquette_langue(titre: str) -> str:
    """« [fr] » après un titre étranger : le lecteur sait pourquoi il ne le comprend pas."""
    langue = detecter_langue(titre)
    if not langue or langue == "en":
        return ""
    return f' <small style="color:#888">[{langue}]</small>'


'''
texte = texte.replace(ancre6, etiquette + ancre6, 1)

# --- 6. La ligne de compte, au pied du rapport ---------------------------------------
ancre7 = "    if SHOW_COUNTRY_LINKS:"
assert ancre7 in texte
compte = '''    if LANGUES_ECARTEES:
        detail = ", ".join(f"{nom} ({n})" for nom, n in LANGUES_ECARTEES.items())
        parts.append(
            '<p style="font-size:11px;color:#888">🌐 Titles in a script we cannot read were '
            f"dropped: {e(detail)}</p>"
        )
'''
texte = texte.replace(ancre7, compte + ancre7, 1)

# --- 7. Ransomware.live est multilingue par nature -----------------------------------
ancre8 = '"url": "https://ransomware.live/cyberattacks.xml"'
if ancre8 in texte:
    texte = texte.replace(ancre8, ancre8 + ', "multilingue": True', 1)
    print("ransomware.live marque multilingue")

VEILLE.write_text(texte, encoding="utf-8")
print("langues : detection, etiquette, ecartement et compte en place")
