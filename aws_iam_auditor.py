import boto3
import csv
from datetime import datetime, timezone

# ── CONNEXION AWS ─────────────────────────────────────────
iam = boto3.client('iam')

print("✅ Connexion AWS IAM réussie\n")

# ── CONFIGURATION ─────────────────────────────────────────
POLICIES_RISQUE = ["AdministratorAccess", "PowerUserAccess", "IAMFullAccess"]
AGE_CLE_MAX = 90  # jours

# ── RÉCUPÉRER TOUS LES USERS ──────────────────────────────
response = iam.list_users()
users = response['Users']

risques = []

print(f"=== AUDIT AWS IAM — {len(users)} users trouvés ===\n")

for user in users:
    username = user['UserName']
    created = user['CreateDate']
    age_compte = (datetime.now(timezone.utc) - created).days
    findings = []

    # ── CHECK 1 : Policies à risque ───────────────────────
    policies_response = iam.list_attached_user_policies(UserName=username)
    policies = [p['PolicyName'] for p in policies_response['AttachedPolicies']]
    policies_dangereuses = [p for p in policies if p in POLICIES_RISQUE]
    
    if policies_dangereuses:
        findings.append(f"OVERPERMISSIONED: {', '.join(policies_dangereuses)}")

    # ── CHECK 2 : Access keys trop vieilles ───────────────
    keys_response = iam.list_access_keys(UserName=username)
    for key in keys_response['AccessKeyMetadata']:
        if key['Status'] == 'Active':
            age_cle = (datetime.now(timezone.utc) - key['CreateDate']).days
            if age_cle > AGE_CLE_MAX:
                findings.append(f"OLD ACCESS KEY: {age_cle} jours")

    # ── CHECK 3 : MFA désactivé ───────────────────────────
    mfa_response = iam.list_mfa_devices(UserName=username)
    if user.get('PasswordLastUsed') and not mfa_response['MFADevices']:
        findings.append("NO MFA")

    # ── RÉSULTAT ──────────────────────────────────────────
    if findings:
        niveau = "🚨" if any("OVERPERMISSIONED" in f for f in findings) else "⚠️"
        print(f"{niveau} {username}:")
        for f in findings:
            print(f"   → {f}")
        risques.append({
            "username": username,
            "age_compte_jours": age_compte,
            "findings": " | ".join(findings),
            "action": "Réviser immédiatement"
        })
    else:
        print(f"✅ {username} — OK")

# ── EXPORT CSV ────────────────────────────────────────────
nom_fichier = f"rapport_aws_iam_{datetime.now().strftime('%Y-%m-%d')}.csv"

with open(nom_fichier, "w", newline="") as output:
    colonnes = ["username", "age_compte_jours", "findings", "action"]
    writer = csv.DictWriter(output, fieldnames=colonnes)
    writer.writeheader()
    for r in risques:
        writer.writerow(r)

print(f"\nTotal à risque : {len(risques)} / {len(users)} users")
print(f"📄 Rapport exporté : {nom_fichier}")
print("\n=== Audit terminé ===")