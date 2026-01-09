import requests
import re
import csv
import time
import pandas as pd

# Configuration initiale
BASE_URL = "https://www.cert.ssi.gouv.fr"
CVE_PATTERN = r"CVE-\d{4}-\d{4,7}"
OUTPUT_FILE = "donnees_consolidees.csv"

def clean_text(text):
    """Nettoie le texte en remplaçant les retours à la ligne et caractères problématiques"""
    if text == "N/A" or not text:
        return text
    # Remplace les retours à la ligne par des espaces et nettoie les espaces multiples
    cleaned = str(text).replace('\n', ' ').replace('\r', ' ').replace('\t', ' ')
    # Supprime les espaces multiples
    cleaned = ' '.join(cleaned.split())
    return cleaned

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
final_rows = []
print(f"Traitement de {len(bulletins_data)} bulletins...")

for bull in bulletins_data:
    for cve in bull["cves"]:
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
        # Respect du Rate Limiting (2 sec recommandées) 
        time.sleep(2)

# --- PHASE 3 : SAUVEGARDE ---
df = pd.DataFrame(final_rows)
# Export CSV avec gestion correcte des guillemets et retours à la ligne
df.to_csv(OUTPUT_FILE, index=False, encoding='utf-8', quoting=csv.QUOTE_MINIMAL, line_terminator='\n')
print(f"Extraction terminée. Fichier '{OUTPUT_FILE}' généré.")
