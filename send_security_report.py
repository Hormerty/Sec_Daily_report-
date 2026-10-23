import os
import requests
from bs4 import BeautifulSoup
from deep_translator import GoogleTranslator
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Utilisation prioritaires des flux RSS (beaucoup plus stables et fiables que le scraping direct)
SOURCES_RSS = [
    {"nom": "Korben", "url": "https://korben.info/feed"},
    {"nom": "Zataz", "url": "https://www.zataz.com/feed/"},
    {"nom": "Processus.site", "url": "https://processus.site/feed/"},
    {"nom": "Hak5", "url": "https://hak5.org/blogs/rss"},
    {"nom": "HackerSploit", "url": "https://hackersploit.org/feed/"},
    {"nom": "NetworkChuck", "url": "https://networkchuck.com/feed/"}
]

def recuperer_articles_rss(source):
    articles = []
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    }
    try:
        response = requests.get(source["url"], headers=headers, timeout=10)
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'xml') # Analyse du flux RSS/XML
            items = soup.find_all('item')[:3] # Récupère les 3 derniers articles par source
            
            for item in items:
                titre = item.find('title').text.strip() if item.find('title') else "Article sans titre"
                link = item.find('link').text.strip() if item.find('link') else source["url"]
                articles.append({
                    "source": source["nom"],
                    "titre": titre,
                    "lien": link
                })
    except Exception as e:
        print(f"Erreur lors de la récupération pour {source['nom']}: {e}")
    return articles

def recuperer_cisa_json():
    """Récupère directement les vulnérabilités CISA au format JSON officiel"""
    articles = []
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    headers = {'User-Agent': 'Mozilla/5.0'}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])[-5:] # Top 5 plus récentes
            for vuln in reversed(vulnerabilities):
                cve = vuln.get('cveID', 'CVE Inconnu')
                product = vuln.get('product', 'Produit inconnu')
                summary = vuln.get('shortDescription', 'Pas de description')
                
                articles.append({
                    "source": "CISA Alertes",
                    "titre": f"[{cve}] {product} : {summary}",
                    "lien": f"https://nvd.nist.gov/vuln/detail/{cve}"
                })
    except Exception as e:
        print(f"Erreur lors de la récupération CISA: {e}")
    return articles

def generer_rapport():
    tous_les_articles = []
    
    # 1. Alertes CISA officielles
    tous_les_articles.extend(recuperer_cisa_json())
    
    # 2. Articles RSS des blogs OSINT / Cyber
    for source in SOURCES_RSS:
        tous_les_articles.extend(recuperer_articles_rss(source))
        
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
    
    html_body = """
    <html>
      <body style="font-family: Arial, sans-serif; color: #333; line-height: 1.6;">
        <h2 style="color: #d9534f; border-bottom: 2px solid #d9534f; padding-bottom: 5px;">
            🛡️ Rapport Global de Veille Cybersécurité & OSINT
        </h2>
        <p>Voici les dernières actualités et alertes collectées de vos sources surveillées :</p>
        <hr>
        <ul style="list-style-type: none; padding-left: 0;">
    """
    
    if articles:
        translator = GoogleTranslator(source='auto', target='fr')
        for art in articles:
            try:
                titre_traduit = translator.translate(art['titre'][:400])
            except Exception:
                titre_traduit = art['titre']
                
            html_body += f"""
            <li style="margin-bottom: 18px; padding: 10px; background-color: #f8f9fa; border-left: 4px solid #0275d8; border-radius: 4px;">
                <strong style="color: #0275d8;">[{art['source']}]</strong> {titre_traduit}<br>
                <a href="{art['lien']}" target="_blank" style="color: #d9534f; font-weight: bold; text-decoration: none;">🔗 Lire l'article complet</a>
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
