import boto3
import csv
from datetime import datetime, timezone

# ── CONNEXION AWS ─────────────────────────────────────────
iam = boto3.client('iam')

print("✅ Connexion AWS IAM réussie\n")

# ── RÉCUPÉRER TOUS LES USERS ──────────────────────────────
response = iam.list_users()
users = response['Users']

# ── POLITIQUES À RISQUE ───────────────────────────────────
POLICIES_RISQUE = [
    "AdministratorAccess",
    "PowerUserAccess",
    "IAMFullAccess"
]

risques = []

print(f"=== AUDIT AWS IAM — {len(users)} users trouvés ===\n")

for user in users:
    username = user['UserName']
    created = user['CreateDate']
    age_jours = (datetime.now(timezone.utc) - created).days

    # Vérifier les policies attachées
    policies_response = iam.list_attached_user_policies(UserName=username)
    policies = [p['PolicyName'] for p in policies_response['AttachedPolicies']]

    # Détecter les policies à risque
    policies_dangereuses = [p for p in policies if p in POLICIES_RISQUE]

    if policies_dangereuses:
        risques.append({
            "username": username,
            "age_jours": age_jours,
            "policies": ", ".join(policies_dangereuses),
            "action": "Réviser et appliquer least privilege"
        })
        print(f"🚨 {username} — Policies à risque : {', '.join(policies_dangereuses)}")
    else:
        print(f"✅ {username} — OK")

# ── EXPORT CSV ────────────────────────────────────────────
nom_fichier = f"rapport_aws_iam_{datetime.now().strftime('%Y-%m-%d')}.csv"

with open(nom_fichier, "w", newline="") as output:
    colonnes = ["username", "age_jours", "policies", "action"]
    writer = csv.DictWriter(output, fieldnames=colonnes)
    writer.writeheader()
    for r in risques:
        writer.writerow(r)

print(f"\nTotal à risque : {len(risques)} / {len(users)} users")
print(f"📄 Rapport exporté : {nom_fichier}")
print("\n=== Audit terminé ===")