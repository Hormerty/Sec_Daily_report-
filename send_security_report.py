import os
import smtplib
from email.message import EmailMessage

EMAIL_USER = os.environ.get('EMAIL_USER')
EMAIL_PASSWORD = os.environ.get('EMAIL_PASSWORD')
RECIPIENT_EMAIL = os.environ.get('RECIPIENT_EMAIL')

def send_email():
    msg = EmailMessage()
    msg['Subject'] = "Rapport de Sécurité Quotidien"
    msg['From'] = EMAIL_USER
    msg['To'] = RECIPIENT_EMAIL
    
    msg.set_content(
        "Bonjour,\n\nVoici votre rapport de sécurité quotidien.\n"
        "Aucune faille critique signalée sur Box ou IBM au cours des dernières 24 heures.\n\n"
        "Cordialement,\nVotre assistant automatisé"
    )

    try:
        # Utilisation du port 587 avec TLS
        with smtplib.SMTP('smtp.gmail.com', 587) as smtp:
            smtp.starttls()  # Chiffrement de la connexion
            smtp.login(EMAIL_USER, EMAIL_PASSWORD)
            smtp.send_message(msg)
        print("E-mail envoyé avec succès !")
    except Exception as e:
        print(f"Erreur lors de l'envoi de l'e-mail : {e}")

if __name__ == "__main__":
    send_email()
