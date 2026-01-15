import requests
import re
import csv
import time
import pandas as pd
import json
import os


# Configuration initiale
BASE_URL = "https://www.cert.ssi.gouv.fr"
CVE_PATTERN = r"CVE-\d{4}-\d{4,7}"
OUTPUT_FILE = "donnees_consolidees.csv"
PROCESSED_CVES_FILE = "processed_cves.json"


def clean_text(text):
    """Nettoie le texte en remplaçant les retours à la ligne et caractères problématiques"""
    if text == "N/A" or not text:
        return text
    # Remplace les retours à la ligne par des espaces et nettoie les espaces multiples
    cleaned = str(text).replace('\n', ' ').replace('\r', ' ').replace('\t', ' ')
    # Supprime les espaces multiples
    cleaned = ' '.join(cleaned.split())
    return cleaned


def load_processed_cves():
    """Charge la liste des CVE déjà traitées depuis le fichier JSON"""
    if os.path.exists(PROCESSED_CVES_FILE):
        try:
            with open(PROCESSED_CVES_FILE, 'r', encoding='utf-8') as f:
                return set(json.load(f))
        except Exception as e:
            print(f"Erreur lors du chargement des CVE traitées: {e}")
            return set()
    return set()

def save_processed_cve(cve_id, processed_cves):
    """Ajoute une CVE à la liste des CVE traitées et sauvegarde"""
    processed_cves.add(cve_id)
    try:
        with open(PROCESSED_CVES_FILE, 'w', encoding='utf-8') as f:
            json.dump(list(processed_cves), f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"Erreur lors de la sauvegarde des CVE traitées: {e}")


def get_severity(cvss_score):
    """Détermine la sévérité selon le standard CVSS [cite: 94, 95, 96, 97]"""
    if cvss_score == "N/A": return "Inconnue"
    score = float(cvss_score)
    if 0 <= score <= 3: return "Faible"
    if 4 <= score <= 6: return "Moyenne"
    if 7 <= score <= 8: return "Élevée"
    if 9 <= score <= 10: return "Critique"
    return "Inconnue"


def enrich_cve_data(cve_id):
    """Enrichit une CVE via les API MITRE et EPSS """
    # 1. API MITRE (Score CVSS, CWE, Produits)
    url_mitre = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    details = {
        "score": "N/A", "cwe": "N/A", "desc": "N/A",
        "vendor": "N/A", "product": "N/A", "versions": "N/A"
    }
   
    try:
        resp = requests.get(url_mitre, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            cna = data.get("containers", {}).get("cna", {})
           
            # Description et Métriques [cite: 110, 112]
            desc_raw = cna.get("descriptions", [{}])[0].get("value", "N/A")
            details["desc"] = clean_text(desc_raw)[:150] if desc_raw != "N/A" else "N/A"
            metrics = cna.get("metrics", [{}])[0]
            cvss = metrics.get("cvssV3_1", metrics.get("cvssV3_0", {}))
            details["score"] = cvss.get("baseScore", "N/A")
           
            # CWE [cite: 118]
            problem = cna.get("problemTypes", [{}])[0].get("descriptions", [{}])[0]
            details["cwe"] = problem.get("cweId", "N/A")
           
            # Produits affectés [cite: 121, 125]
            affected = cna.get("affected", [{}])[0]
            details["vendor"] = clean_text(affected.get("vendor", "N/A"))
            details["product"] = clean_text(affected.get("product", "N/A"))
            v_list = [clean_text(v.get("version", "")) for v in affected.get("versions", []) if v.get("status") == "affected"]
            details["versions"] = ", ".join(v_list) if v_list else "N/A"
           
    except Exception as e:
        print(f"Erreur MITRE pour {cve_id}: {e}")


    # 2. API EPSS (Probabilité d'exploitation) [cite: 140]
    url_epss = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    details["epss"] = "N/A"
    try:
        resp_epss = requests.get(url_epss, timeout=5).json()
        epss_data = resp_epss.get("data", [])
        if epss_data:
            details["epss"] = epss_data[0].get("epss", "N/A")
    except Exception:
        pass
    
       
    return details


# --- PHASE 1 : SCRAPPING ANSSI ---
bulletins_data = []
print("Recherche des bulletins ANSSI...")

for page in range(1, 3): # Limité à 2 pages pour l'exemple
    url = f"{BASE_URL}/alerte/" if page == 1 else f"{BASE_URL}/alerte/page/{page}/"
    html = requests.get(url).text
    links = re.findall(r'href="(/alerte/CERTFR-[^/]+/)"', html)
   
    for alerte_path in set(links):
        json_url = f"{BASE_URL}{alerte_path}json/"
        try:
            data = requests.get(json_url).json()
            # On stocke l'alerte et la liste des CVE associées [cite: 80, 85]
            cve_found = list(set(re.findall(CVE_PATTERN, str(data))))
            bulletins_data.append({
                "titre": data.get("title", "N/A"),
                "type": "Alerte",
                "date": data.get("date", "N/A"),
                "lien": f"{BASE_URL}{alerte_path}",
                "cves": cve_found
            })
        except: continue


# --- PHASE 2 : ENRICHISSEMENT ET CONSOLIDATION ---
# Chargement des CVE déjà traitées
processed_cves = load_processed_cves()
print(f"CVE déjà traitées: {len(processed_cves)}")

final_rows = []
new_cves_count = 0
skipped_cves_count = 0

print(f"Traitement de {len(bulletins_data)} bulletins...")

for bull in bulletins_data:
    for cve in bull["cves"]:
        # Vérifier si la CVE a déjà été traitée
        if cve in processed_cves:
            print(f"CVE {cve} déjà traitée, ignorée.")
            skipped_cves_count += 1
            continue
        
        print(f"Enrichissement de {cve}...")
        enriched = enrich_cve_data(cve)
       
        # Création de la ligne consolidée [cite: 153, 277]
        final_rows.append({
            "Titre ANSSI": clean_text(bull["titre"]),
            "Type": bull["type"],
            "Date": bull["date"],
            "CVE ID": cve,
            "CVSS Score": enriched["score"],
            "Base Severity": get_severity(enriched["score"]),
            "CWE": enriched["cwe"],
            "EPSS": enriched["epss"],
            "Lien": bull["lien"],
            "Description": enriched["desc"],
            "Editeur": enriched["vendor"],
            "Produit": enriched["product"],
            "Versions": enriched["versions"]
        })
        
        # Enregistrer la CVE comme traitée
        save_processed_cve(cve, processed_cves)
        new_cves_count += 1
        
        # Respect du Rate Limiting (2 sec recommandées)
        time.sleep(2)

print(f"\nRésumé: {new_cves_count} nouvelles CVE traitées, {skipped_cves_count} CVE ignorées (déjà traitées)")


# --- PHASE 3 : SAUVEGARDE ---
df = pd.DataFrame(final_rows)
# Export CSV avec gestion correcte des guillemets et retours à la ligne
df.to_csv(OUTPUT_FILE, index=False, encoding='utf-8', quoting=csv.QUOTE_MINIMAL, lineterminator='\n')
print(f"Extraction terminée. Fichier '{OUTPUT_FILE}' généré.")

import smtplib 
from email.mime.text import MIMEText 

# Dictionnaire des utilisateurs et leurs abonnements aux newsletters
# Chaque utilisateur peut être abonné à plusieurs entreprises/produits
users_subscriptions = {
    "ivantiprojetS5@email.com": ["Ivanti", "Connect Secure", "Policy Secure"],
    "citrixprojetS5@email.com": ["Citrix", "NetScaler", "ADC", "Gateway"],
    "msharpointprojetS5@email.com": ["Microsoft", "SharePoint"],
    "FortinetprojetS5@email.com": ["Fortinet", "FortiOS", "FortiGate", "FortiManager", "FortiProxy", "FortiVoice"],
    "ciscoprojetS5@email.com": ["Cisco", "ASA", "FTD"],
    "RSCccccprojets5@email.com": ["React", "Meta", "react-server"],
    "OpCUPSprojetS5@email.com": ["OpenPrinting", "CUPS", "cups-browsed", "libcupsfilters", "libppd"],
    "SAPNetprojetS5@email.com": ["SAP", "NetWeaver"],
    "UnknownCVEprojetS5@email.com": []  # Abonné à toutes les alertes inconnues
}

def send_email(to_email, subject, body): 
    """Envoie un email d'alerte"""
    from_email = "projets5esilvv@gmail.com"
    password = "edhj dtlg jiff yjgh" 
    try:
        msg = MIMEText(body, 'plain', 'utf-8') 
        msg['From'] = from_email 
        msg['To'] = to_email 
        msg['Subject'] = subject 
        server = smtplib.SMTP('smtp.gmail.com', 587) 
        server.starttls() 
        server.login(from_email, password) 
        server.sendmail(from_email, to_email, msg.as_string()) 
        server.quit()
        return True
    except Exception as e:
        print(f"Erreur lors de l'envoi de l'email à {to_email}: {e}")
        return False

def create_alert_message(cve_row):
    """Crée le message d'alerte détaillé pour une CVE"""
    message = f"""Alerte de sécurité critique détectée !

CVE ID: {cve_row['CVE ID']}
Titre ANSSI: {cve_row['Titre ANSSI']}
Date: {cve_row['Date']}

Détails de la vulnérabilité:
- Score CVSS: {cve_row['CVSS Score']}
- Sévérité: {cve_row['Base Severity']}
- CWE: {cve_row['CWE']}
- EPSS (probabilité d'exploitation): {cve_row['EPSS']}

Produit affecté:
- Éditeur: {cve_row['Editeur']}
- Produit: {cve_row['Produit']}
- Versions: {cve_row['Versions']}

Description: {cve_row['Description']}

Lien vers l'alerte ANSSI: {cve_row['Lien']}

Veuillez prendre les mesures nécessaires pour sécuriser vos systèmes.
"""
    return message

def check_subscription_match(user_subscriptions, vendor, product, titre):
    """Vérifie si l'utilisateur est abonné à l'entreprise/produit concerné"""
    # Si la liste est vide, l'utilisateur est abonné à toutes les alertes (cas des alertes inconnues)
    if not user_subscriptions:
        return True
    
    search_text = f"{vendor} {product} {titre}".lower()
    for subscription in user_subscriptions:
        if subscription.lower() in search_text:
            return True
    return False

# --- PHASE 4 : ENVOI D'ALERTES PAR EMAIL ---
print("\nAnalyse des CVE critiques pour envoi d'alertes...")
critical_cves_sent = 0

# Parcourir toutes les CVE traitées et identifier les critiques
for cve_row in final_rows:
    severity = cve_row['Base Severity']
    
    # Traiter uniquement les CVE critiques
    if severity == "Critique":
        vendor = cve_row['Editeur']
        product = cve_row['Produit']
        titre = cve_row['Titre ANSSI']
        
        # Parcourir tous les utilisateurs et leurs abonnements
        for user_email, subscriptions in users_subscriptions.items():
            # Vérifier si l'utilisateur est abonné à cette entreprise/produit
            if check_subscription_match(subscriptions, vendor, product, titre):
                subject = f"Alerte CVE critique - {cve_row['CVE ID']}"
                body = create_alert_message(cve_row)
                
                if send_email(user_email, subject, body):
                    print(f"Email envoyé à {user_email} pour {cve_row['CVE ID']} ({vendor}/{product})")
                    critical_cves_sent += 1
                else:
                    print(f"Échec d'envoi à {user_email} pour {cve_row['CVE ID']}")
        
        # Gestion des CVE inconnues (pas de vendor/product identifié)
        # Vérifier si un utilisateur est abonné aux alertes inconnues
        if vendor == "N/A" and product == "N/A":
            unknown_email = "UnknownCVEprojetS5@email.com"
            if unknown_email in users_subscriptions and check_subscription_match(users_subscriptions[unknown_email], vendor, product, titre):
                subject = f"Alerte CVE critique inconnue - {cve_row['CVE ID']}"
                body = create_alert_message(cve_row)
                if send_email(unknown_email, subject, body):
                    print(f"Email envoyé à {unknown_email} pour CVE inconnue {cve_row['CVE ID']}")
                    critical_cves_sent += 1

print(f"\nTotal d'emails d'alerte envoyés: {critical_cves_sent}")
      
