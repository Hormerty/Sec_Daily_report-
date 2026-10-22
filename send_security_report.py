import os
import smtplib
import ssl
from email.message import EmailMessage
import requests

EMAIL_USER = os.environ.get('EMAIL_USER')
EMAIL_PASSWORD = os.environ.get('EMAIL_PASSWORD')
RECIPIENT_EMAIL = os.environ.get('RECIPIENT_EMAIL')

def fetch_global_security_alerts():
    """
    Récupère automatiquement les dernières failles critiques et activement 
    exploitées à l'échelle mondiale via le catalogue public CISA KEV.
    """
    report_lines = []
    
    try:
        # Catalogue officiel des vulnérabilités connues et exploitées
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        response = requests.get(url, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])
            
            # Sélection des 20 failles les plus récemment ajoutées au catalogue mondial
            recent_vulns = vulnerabilities[-5:]
            
            report_lines.append("Dernières failles critiques et exploitées (Veille Mondiale CISA) :\n")
            for vuln in recent_vulns:
                cve = vuln.get('cveID', 'CVE Inconnue')
                name = vuln.get('vulnerabilityName', 'Nom non spécifié')
                vendor = vuln.get('vendorProject', 'Fournisseur')
                product = vuln.get('product', 'Produit')
                report_lines.append(f"• [{cve}] {vendor} - {product} : {name}")
        else:
            report_lines.append(f"Impossible de joindre la base de données mondiale (Code HTTP {response.status_code})")

    except Exception as e:
        report_lines.append(f"Erreur lors de la récupération des failles globales : {e}")

    return "\n".join(report_lines)

def send_email():
    alerts_summary = fetch_global_security_alerts()
    
    msg = EmailMessage()
    msg['Subject'] = "Rapport Global de Sécurité Quotidien"
    msg['From'] = EMAIL_USER
    msg['To'] = RECIPIENT_EMAIL
    
    msg.set_content(
        f"Bonjour,\n\nVoici votre rapport de sécurité global quotidien.\n\n"
        f"{alerts_summary}\n\n"
        f"Cordialement,\nVotre assistant automatisé"
    )

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
            smtp.login(EMAIL_USER, EMAIL_PASSWORD)
            smtp.send_message(msg)
        print("E-mail de rapport global envoyé avec succès !")
    except Exception as e:
        print(f"Erreur lors de l'envoi de l'e-mail : {e}")

if __name__ == "__main__":
    send_email()
