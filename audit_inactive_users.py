import csv
import sys
from datetime import datetime, timedelta

# Seuil configurable — défaut 90 jours si rien spécifié
jours_seuil = int(sys.argv[1]) if len(sys.argv) > 1 else 90
seuil = datetime.now() - timedelta(days=jours_seuil)

print(f"Seuil configuré : {jours_seuil} jours\n")

inactifs = []

# Lire les users depuis le fichier CSV
with open("users.csv", newline="") as fichier:
    reader = csv.DictReader(fichier)
    
    for user in reader:
        last_login = datetime.strptime(user["last_login"], "%Y-%m-%d")
        
        if last_login < seuil:
            jours = (datetime.now() - last_login).days
            inactifs.append({
                "name": user["name"],
                "department": user["department"],
                "jours": jours
            })
inactifs.sort(key=lambda x: x["jours"], reverse=True)
# Afficher le rapport
print("=== AUDIT — Comptes inactifs (90+ jours) ===\n")

for compte in inactifs:
    print(f"⚠️  {compte['name']} ({compte['department']}) — inactif depuis {compte['jours']} jours")

print(f"\nTotal à risque : {len(inactifs)} / 8 comptes")
# Exporter le rapport en CSV
nom_fichier = f"rapport_audit_{datetime.now().strftime('%Y-%m-%d')}.csv"

with open(nom_fichier, "w", newline="") as output:
    colonnes = ["name", "department", "jours", "action"]
    writer = csv.DictWriter(output, fieldnames=colonnes)
    
    writer.writeheader()
    
    for compte in inactifs:
        writer.writerow({
            "name": compte["name"],
            "department": compte["department"],
            "jours": compte["jours"],
            "action": "Désactiver ou valider avec manager"
        })

print(f"\n📄 Rapport exporté : {nom_fichier}")
print("=== Audit terminé ===")