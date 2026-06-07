import boto3
import requests
import msal
import csv
from datetime import datetime, timezone
from config import TENANT_ID, CLIENT_ID, CLIENT_SECRET

# ══════════════════════════════════════════════════════════
# CONFIGURATION
# ══════════════════════════════════════════════════════════
AGE_CLE_MAX = 90  # jours
POLICIES_RISQUE = ["AdministratorAccess", "PowerUserAccess", "IAMFullAccess"]

inventaire = []

# ══════════════════════════════════════════════════════════
# FONCTION : CALCUL DU SCORE DE RISQUE
# ══════════════════════════════════════════════════════════
def calculer_risque(findings):
    score = 0
    for f in findings:
        if "OVERPERMISSIONED" in f:
            score += 40
        if "OLD KEY" in f or "OLD SECRET" in f:
            score += 30
        if "NO MFA" in f:
            score += 20
        if "NO ACTIVITY" in f:
            score += 10
    
    if score >= 60:
        return score, "CRITIQUE"
    elif score >= 30:
        return score, "ÉLEVÉ"
    elif score > 0:
        return score, "MOYEN"
    else:
        return 0, "OK"

# ══════════════════════════════════════════════════════════
# SOURCE 1 : AWS IAM
# ══════════════════════════════════════════════════════════
print("🔍 Scan AWS IAM...\n")

iam = boto3.client('iam')
users = iam.list_users()['Users']

for user in users:
    username = user['UserName']
    findings = []

    # Skip les comptes humains évidents
    if not any(prefix in username.lower() for prefix in ['svc', 'app', 'bot', 'svc', 'service', 'api']):
        continue

    # Check 1 : Policies à risque
    policies = iam.list_attached_user_policies(UserName=username)['AttachedPolicies']
    policies_noms = [p['PolicyName'] for p in policies]
    dangereuses = [p for p in policies_noms if p in POLICIES_RISQUE]
    if dangereuses:
        findings.append(f"OVERPERMISSIONED: {', '.join(dangereuses)}")

    # Check 2 : Access keys trop vieilles
    keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']
    for key in keys:
        if key['Status'] == 'Active':
            age = (datetime.now(timezone.utc) - key['CreateDate']).days
            if age > AGE_CLE_MAX:
                findings.append(f"OLD KEY: {age} jours")

    # Check 3 : Aucune activité
    if not user.get('PasswordLastUsed'):
        findings.append("NO ACTIVITY")

    score, niveau = calculer_risque(findings)

    inventaire.append({
        "cloud_provider": "AWS",
        "type": "IAM User (Service)",
        "identite": username,
        "findings": " | ".join(findings) if findings else "Aucun",
        "score_risque": score,
        "niveau_risque": niveau,
        "action": "Réviser" if findings else "OK"
    })

# ══════════════════════════════════════════════════════════
# SOURCE 2 : AZURE — SERVICE PRINCIPALS
# ══════════════════════════════════════════════════════════
print("🔍 Scan Azure Service Principals...\n")

# Authentification
app = msal.ConfidentialClientApplication(
    CLIENT_ID,
    authority=f"https://login.microsoftonline.com/{TENANT_ID}",
    client_credential=CLIENT_SECRET
)

token = app.acquire_token_for_client(
    scopes=["https://graph.microsoft.com/.default"]
)

if "access_token" not in token:
    print("❌ Erreur auth Azure")
else:
    headers = {"Authorization": f"Bearer {token['access_token']}"}

    # Récupérer les App Registrations
    url = "https://graph.microsoft.com/v1.0/applications?$select=displayName,createdDateTime,passwordCredentials"
    response = requests.get(url, headers=headers)
    apps = response.json().get("value", [])

    for app_reg in apps:
        nom = app_reg['displayName']
        findings = []
        created = datetime.fromisoformat(
            app_reg['createdDateTime'].replace('Z', '+00:00')
        )
        age_jours = (datetime.now(timezone.utc) - created).days

        # Check : secrets expirés ou trop vieux
        for secret in app_reg.get('passwordCredentials', []):
            end_date = datetime.fromisoformat(
                secret['endDateTime'].replace('Z', '+00:00')
            )
            age_secret = (datetime.now(timezone.utc) - created).days
            
            if end_date < datetime.now(timezone.utc):
                findings.append("EXPIRED SECRET")
            elif age_secret > AGE_CLE_MAX:
                findings.append(f"OLD SECRET: {age_secret} jours")

        if not app_reg.get('passwordCredentials'):
            findings.append("NO CREDENTIALS CONFIGURED")

        score, niveau = calculer_risque(findings)

        inventaire.append({
            "cloud_provider": "Azure",
            "type": "App Registration",
            "identite": nom,
            "findings": " | ".join(findings) if findings else "Aucun",
            "score_risque": score,
            "niveau_risque": niveau,
            "action": "Réviser" if findings else "OK"
        })

# ══════════════════════════════════════════════════════════
# RAPPORT UNIFIÉ
# ══════════════════════════════════════════════════════════

# Trier par score de risque décroissant
inventaire.sort(key=lambda x: x["score_risque"], reverse=True)

print("=== INVENTAIRE NHI UNIFIÉ ===\n")
for nhi in inventaire:
    emoji = "🚨" if nhi['niveau_risque'] == "CRITIQUE" else \
            "⚠️" if nhi['niveau_risque'] == "ÉLEVÉ" else \
            "🟡" if nhi['niveau_risque'] == "MOYEN" else "✅"
    print(f"{emoji} [{nhi['cloud_provider']}] {nhi['identite']} — {nhi['niveau_risque']} (score: {nhi['score_risque']})")
    if nhi['findings'] != "Aucun":
        print(f"   → {nhi['findings']}")

# Export CSV unifié
nom_fichier = f"nhi_inventory_{datetime.now().strftime('%Y-%m-%d')}.csv"

with open(nom_fichier, "w", newline="", encoding="utf-8") as output:
    colonnes = ["cloud_provider", "type", "identite", "findings", "score_risque", "niveau_risque", "action"]
    writer = csv.DictWriter(output, fieldnames=colonnes)
    writer.writeheader()
    for nhi in inventaire:
        writer.writerow(nhi)

critiques = len([n for n in inventaire if n['niveau_risque'] == "CRITIQUE"])
print(f"\nTotal NHI inventoriées : {len(inventaire)}")
print(f"Critiques : {critiques}")
print(f"📄 Rapport exporté : {nom_fichier}")
print("\n=== Scan terminé ===")