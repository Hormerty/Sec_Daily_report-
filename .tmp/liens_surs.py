"""Filtre les liens du rapport quotidien : plus de javascript: ni de data: dans un href."""
from pathlib import Path

VEILLE = Path(r"D:\Security Code GitHub\Sec_Daily_report-\veille.py")
texte = VEILLE.read_text(encoding="utf-8")

# 1. L'aide, juste avant render_html, qui l'utilise.
ancre = "def render_html(groups: dict[str, list[Article]], errors: list[str],"
assert ancre in texte, "render_html introuvable"
aide = '''def _lien_html(url: str, texte: str) -> str:
    """Un lien seulement s'il mène quelque part de sûr.

    Un flux peut annoncer `javascript:` ou `data:` : le rendu de l'alerte filtrait déjà les
    schémas, le rapport quotidien non. Le rapport s'ouvre dans un navigateur (bouton « Ouvrir
    le dernier rapport ») : un lien de ce genre y exécutait du script dans l'origine du fichier.
    """
    url = str(url or "")
    if url.startswith(("http://", "https://")):
        return (f'<a href="{html.escape(url, quote=True)}" target="_blank" '
                f'rel="noopener noreferrer">{html.escape(str(texte))}</a>')
    return html.escape(str(texte))


'''
texte = texte.replace(ancre, aide + ancre, 1)

remplacements = [
    # Liste des plus critiques.
    ('''                f'<a href="{e(a.link, quote=True)}" target="_blank" rel="noopener noreferrer">{e(a.title)}</a>{metr} '
                f'<small>({e(a.source)})</small>{qual_html}{cve_html}</li>\'''',
     '''                f'{_lien_html(a.link, a.title)}{metr} '
                f'<small>({e(a.source)})</small>{qual_html}{cve_html}</li>\''''),
    # « Also covered by ».
    ('''                f'<a href="{e(link, quote=True)}" target="_blank" rel="noopener noreferrer">{e(src)}</a>\'''',
     '''                f'{_lien_html(link, src)}\''''),
    # Liste principale.
    ('''                f'<a href="{e(a.link, quote=True)}" target="_blank" rel="noopener noreferrer">{e(a.title)}</a>{metr}{detail}{qual_html}{also}</li>\'''',
     '''                f'{_lien_html(a.link, a.title)}{metr}{detail}{qual_html}{also}</li>\''''),
    # Section « votre stack ».
    ('''                    f'<a href="{e(a.link, quote=True)}" target="_blank" rel="noopener noreferrer">'
                    f"{e(a.title)}</a> <small>({e(a.source)})</small></li>\'''',
     '''                    f'{_lien_html(a.link, a.title)} <small>({e(a.source)})</small></li>\''''),
    # Section « pays IBM ».
    ('''                    f'<a href="{e(a.link, quote=True)}" target="_blank" rel="noopener noreferrer">'
                    f"{e(a.title)}</a> <small>({e(a.source)})</small></li>\'''',
     '''                    f'{_lien_html(a.link, a.title)} <small>({e(a.source)})</small></li>\''''),
]

for avant, apres in remplacements:
    if avant in texte:
        texte = texte.replace(avant, apres, 1)
    else:
        print("  NON TROUVE :", avant.splitlines()[0].strip()[:70])

VEILLE.write_text(texte, encoding="utf-8")
print("veille.py : liens filtres")
print("href non filtres restants :", texte.count('href="{e(a.link'))
