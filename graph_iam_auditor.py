import requests
import msal
import csv
from datetime import datetime, timedelta
from config import TENANT_ID, CLIENT_ID, CLIENT_SECRET

# ── AUTHENTIFICATION ──────────────────────────────────────
app = msal.ConfidentialClientApplication(
    CLIENT_ID,
    authority=f"https://login.microsoftonline.com/{TENANT_ID}",
    client_credential=CLIENT_SECRET
)

token_response = app.acquire_token_for_client(
    scopes=["https://graph.microsoft.com/.default"]
)

if "access_token" not in token_response:
    print("❌ Erreur d'authentification")
    print(token_response.get("error_description"))
    exit()

print("✅ Authentification réussie\n")

# ── APPEL GRAPH API ───────────────────────────────────────
headers = {"Authorization": f"Bearer {token_response['access_token']}"}

url = "https://graph.microsoft.com/v1.0/users?$select=displayName,userPrincipalName,createdDateTime"

response = requests.get(url, headers=headers)
users = response.json().get("value", [])

# ── SIMULER LES DERNIÈRES CONNEXIONS ─────────────────────
# Dans un vrai tenant avec licence P1, on utiliserait signInActivity
# Ici on simule pour démontrer la logique d'audit
simulated_last_login = {
    "bob.tremblay": datetime.now() - timedelta(days=123),
    "carol.dupont": datetime.now() - timedelta(days=149),
    "david.roy":    datetime.now() - timedelta(days=15),
    "emma.gagne":   datetime.now() - timedelta(days=97),
}

# ── LOGIQUE D'AUDIT ───────────────────────────────────────
seuil_jours = 90
seuil = datetime.now() - timedelta(days=seuil_jours)

inactifs = []

print(f"=== AUDIT ENTRA ID — Seuil : {seuil_jours} jours ===\n")

for user in users:
    upn = user["userPrincipalName"]
    nom = user["displayName"]

    # Trouver la clé simulée (prénom.nom)
    cle = upn.split("@")[0].lower()
    last_login = simulated_last_login.get(cle)

    if last_login and last_login < seuil:
        jours = (datetime.now() - last_login).days
        inactifs.append({
            "name": nom,
            "upn": upn,
            "jours": jours,
            "action": "Désactiver ou valider avec manager"
        })
        print(f"⚠️  {nom} — inactif depuis {jours} jours")

# ── TRIER PAR RISQUE ──────────────────────────────────────
inactifs.sort(key=lambda x: x["jours"], reverse=True)

# ── EXPORT CSV ────────────────────────────────────────────
nom_fichier = f"rapport_entra_{datetime.now().strftime('%Y-%m-%d')}.csv"

with open(nom_fichier, "w", newline="") as output:
    colonnes = ["name", "upn", "jours", "action"]
    writer = csv.DictWriter(output, fieldnames=colonnes)
    writer.writeheader()
    for compte in inactifs:
        writer.writerow(compte)

print(f"\nTotal à risque : {len(inactifs)} / {len(users)} comptes")
print(f"📄 Rapport exporté : {nom_fichier}")
print("\n=== Audit terminé ===")