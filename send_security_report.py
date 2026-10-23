import os
import requests
from bs4 import BeautifulSoup
from deep_translator import GoogleTranslator
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Configuration des sources à surveiller (RSS ou pages web principales)
SOURCES = [
    {
        "nom": "CISA (Alertes Officielles)",
        "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "type": "cisa"
    },
    {
        "nom": "Korben (Cybersécurité)",
        "url": "https://korben.info/categories/cybersecurite/",
        "type": "html",
        "selector": "h2.entry-title a"
    },
    {
        "nom": "Zataz",
        "url": "https://www.zataz.com/",
        "type": "html",
        "selector": "h3.ast-loop-title аст-title a, h2.entry-title a"
    },
    {
        "nom": "Processus.site",
        "url": "https://processus.site/",
        "type": "html",
        "selector": "h2.entry-title a"
    }
]

# Mots-clés prioritaires pour mettre en avant les alertes critiques
KEYWORDS_PRIORITAIRES = [
    "node", "node.js", "node2shell", "outlook", "exchange", 
    "microsoft", "ibm", "box", "rce", "cisa", "ransomware", "faille"
]

def recuperer_cisa():
    articles = []
    try:
        url = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            # Extraction basique des lignes du catalogue CISA
            for row in soup.find_all('tr')[:5]: # Limité aux 5 dernières
                cols = row.find_all('td')
                if len(cols) > 1:
                    cve = cols[0].text.strip()
                    nom_produit = cols[1].text.strip()
                    desc = cols[2].text.strip() if len(cols) > 2 else "Alerte critique CISA"
                    articles.append({
                        "source": "CISA",
                        "titre": f"[{cve}] {nom_produit} - {desc}",
                        "lien": url
                    })
    except Exception as e:
        print(f"Erreur CISA: {e}")
    return articles

def recuperer_site_html(source):
    articles = []
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        response = requests.get(source["url"], headers=headers, timeout=10)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            liens = soup.select(source.get("selector", "a"))[:5] # Top 5 articles
            for l in liens:
                titre = l.text.strip()
                href = l.get('href')
                if titre and href:
                    if not href.startswith("http"):
                        # Gérer les liens relatifs si besoin
                        continue
                    articles.append({
                        "source": source["nom"],
                        "titre": titre,
                        "lien": href
                    })
    except Exception as e:
        print(f"Erreur {source['nom']}: {e}")
    return articles

def generer_rapport():
    tous_les_articles = []
    
    # Récupération CISA
    tous_les_articles.extend(recuperer_cisa())
    
    # Récupération des autres sources configurées
    for s in SOURCES[1:]:
        tous_les_articles.extend(recuperer_site_html(s))
        
    return tous_les_articles

def envoyer_email(html_content):
    sender_email = os.environ.get("EMAIL_USER")
    sender_password = os.environ.get("EMAIL_PASSWORD")
    recipient_email = os.environ.get("RECIPIENT_EMAIL")

    message = MIMEMultipart("alternative")
    message["Subject"] = "🛡️ Rapport Global de Sécurité & OSINT Quotidien"
    message["From"] = sender_email
    message["To"] = recipient_email

    part = MIMEText(html_content, "html")
    message.attach(part)

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, recipient_email, message.as_string())
        print("E-mail envoyé avec succès !")
    except Exception as e:
        print(f"Erreur lors de l'envoi de l'e-mail : {e}")

if __name__ == "__main__":
    articles = generer_rapport()
    
    # Construction du contenu HTML avec liens cliquables
    html_body = """
    <html>
      <body style="font-family: Arial, sans-serif; color: #333;">
        <h2 style="color: #d9534f;">🛡️ Rapport Global de Veille Cybersécurité & OSINT</h2>
        <p>Voici les dernières actualités et alertes collectées de vos sources surveillées :</p>
        <hr>
        <ul>
    """
    
    if articles:
        translator = GoogleTranslator(source='auto', target='fr')
        for art in articles:
            # Traduction automatique du titre si nécessaire
            try:
                titre_traduit = translator.translate(art['titre'][:450])
            except:
                titre_traduit = art['titre']
                
            html_body += f"""
            <li style="margin-bottom: 15px;">
                <b>[{art['source']}]</b> {titre_traduit}<br>
                <a href="{art['lien']}" target="_blank" style="color: #0275d8; text-decoration: none;">🔗 Lire l'article complet</a>
            </li>
            """
    else:
        html_body += "<li>Aucune nouvelle alerte récupérée pour le moment.</li>"
        
    html_body += """
        </ul>
        <hr>
        <p style="font-size: 12px; color: #777;">Généré automatiquement par votre NourSECBot via GitHub Actions.</p>
      </body>
    </html>
    """
    
    envoyer_email(html_body)
