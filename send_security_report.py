import os
import smtplib
import ssl
from email.message import EmailMessage
import requests
from deep_translator import GoogleTranslator

EMAIL_USER = os.environ.get('EMAIL_USER')
EMAIL_PASSWORD = os.environ.get('EMAIL_PASSWORD')
RECIPIENT_EMAIL = os.environ.get('RECIPIENT_EMAIL')

def fetch_global_security_alerts_translated():
    """
    Récupère les dernières failles mondiales de la CISA et les traduit automatiquement en français.
    """
    report_lines = []
    
    try:
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        response = requests.get(url, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])
            recent_vulns = vulnerabilities[-5:]  # Sélection des 5 failles les plus récentes
            
            report_lines.append("Dernières failles critiques mondiales (Source CISA - Traduites en français) :\n")
            
            # Initialisation du traducteur vers le français
            translator = GoogleTranslator(source='auto', target='fr')
            
            for vuln in recent_vulns:
                cve = vuln.get('cveID', 'CVE Inconnue')
                name = vuln.get('vulnerabilityName', 'Nom non spécifié')
                vendor = vuln.get('vendorProject', 'Fournisseur')
                product = vuln.get('product', 'Produit')
                
                # Traduction automatique des champs textuels pour un affichage en français
                try:
                    translated_name = translator.translate(name) if name else name
                    translated_vendor = translator.translate(vendor) if vendor else vendor
                    translated_product = translator.translate(product) if product else product
                except Exception:
                    # En cas de micro-coupure du service de traduction, on garde les textes originaux
                    translated_name, translated_vendor, translated_product = name, vendor, product
                
                report_lines.append(f"• [{cve}] {translated_vendor} - {translated_product} : {translated_name}")
        else:
            report_lines.append(f"Impossible de joindre la base de données mondiale (Code HTTP {response.status_code})")

    except Exception as e:
        report_lines.append(f"Erreur lors de la récupération des failles globales : {e}")

    return "\n".join(report_lines)

def send_email():
    alerts_summary = fetch_global_security_alerts_translated()
    
    msg = EmailMessage()
    msg['Subject'] = "Rapport Global de Sécurité Quotidien (Traduit)"
    msg['From'] = EMAIL_USER
    msg['To'] = RECIPIENT_EMAIL
    
    msg.set_content(
        f"Bonjour,\n\nVoici votre rapport de sécurité global quotidien.\n\n"
        f"{alerts_summary}\n\n"
        f"Cordialement,\nNoursBOT"
    )

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
            smtp.login(EMAIL_USER, EMAIL_PASSWORD)
            smtp.send_message(msg)
        print("E-mail de rapport global traduit envoyé avec succès !")
    except Exception as e:
        print(f"Erreur lors de l'envoi de l'e-mail : {e}")

if __name__ == "__main__":
    send_email()
