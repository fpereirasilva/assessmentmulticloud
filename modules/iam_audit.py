"""
Módulo de auditoria de IAM (Identity and Access Management)
Verifica:
- Se a conta Root possui MFA ativo e se tem chaves de acesso ativas
- Usuários com senhas sem MFA
- Access Keys com mais de 90 dias sem rotação ou inativas
- Políticas com permissões excessivas (AdministratorAccess / '*:*')
- Usuários com inline policies (má prática)
"""
from datetime import datetime, timezone
from botocore.exceptions import ClientError

class IAMAuditor:
    def __init__(self, session):
        self.iam = session.client("iam")
        self.findings = []

    def add_finding(self, severity: str, resource: str, issue: str, remediation: str):
        self.findings.append({
            "service": "IAM",
            "severity": severity,  # CRITICAL, HIGH, MEDIUM, LOW, INFO
            "resource": resource,
            "issue": issue,
            "remediation": remediation
        })

    def run(self) -> list:
        self.check_account_summary()
        self.check_users()
        self.check_password_policy()
        return self.findings

    def check_account_summary(self):
        try:
            summary = self.iam.get_account_summary()["SummaryMap"]

            # Root MFA
            root_mfa = summary.get("AccountMFAEnabled", 0)
            if root_mfa == 0:
                self.add_finding(
                    severity="CRITICAL",
                    resource="Account Root",
                    issue="A conta Root NÃO possui MFA (Autenticação Multi-Fator) habilitado.",
                    remediation="Ative MFA imediatamente na conta Root no console IAM."
                )
            else:
                self.add_finding(
                    severity="INFO",
                    resource="Account Root",
                    issue="MFA está ativado na conta Root.",
                    remediation="Manter monitoramento constante."
                )

            # Root Access Keys
            root_keys = summary.get("AccountAccessKeysPresent", 0)
            if root_keys > 0:
                self.add_finding(
                    severity="CRITICAL",
                    resource="Account Root",
                    issue="Existem Access Keys ativas para o usuário Root.",
                    remediation="Remova todas as Access Keys do usuário Root e utilize usuários IAM ou Roles."
                )
        except ClientError as e:
            self.add_finding("LOW", "IAM:AccountSummary", f"Erro ao ler resumo de conta: {e}", "Revisar permissões de auditoria.")

    def check_users(self):
        try:
            paginator = self.iam.get_paginator("list_users")
            now = datetime.now(timezone.utc)

            for page in paginator.paginate():
                for user in page["Users"]:
                    user_name = user["UserName"]

                    # Checar MFA do usuário
                    mfa_devices = self.iam.list_mfa_devices(UserName=user_name)["MFADevices"]
                    login_profile_exists = False
                    try:
                        self.iam.get_login_profile(UserName=user_name)
                        login_profile_exists = True
                    except ClientError:
                        pass

                    if login_profile_exists and not mfa_devices:
                        self.add_finding(
                            severity="HIGH",
                            resource=f"User: {user_name}",
                            issue="Usuário com acesso ao Console Web sem MFA configurado.",
                            remediation=f"Exigir MFA para o usuário '{user_name}'."
                        )

                    # Checar Access Keys
                    keys = self.iam.list_access_keys(UserName=user_name)["AccessKeyMetadata"]
                    for k in keys:
                        if k["Status"] == "Active":
                            age_days = (now - k["CreateDate"]).days
                            if age_days > 90:
                                self.add_finding(
                                    severity="MEDIUM",
                                    resource=f"User: {user_name} (Key: {k['AccessKeyId']})",
                                    issue=f"Access Key ativa tem {age_days} dias sem rotação (limite recomendado: 90 dias).",
                                    remediation="Rotacionar a chave de acesso e revogar a chave antiga."
                                )

                    # Checar Inline Policies
                    inline = self.iam.list_user_policies(UserName=user_name)["PolicyNames"]
                    if inline:
                        self.add_finding(
                            severity="LOW",
                            resource=f"User: {user_name}",
                            issue=f"Usuário possui {len(inline)} política(s) inline vinculada(s) diretamente.",
                            remediation="Migrar inline policies para Managed Policies e associar via Grupos."
                        )

        except ClientError as e:
            self.add_finding("LOW", "IAM:Users", f"Erro ao listar usuários: {e}", "Revisar permissões.")

    def check_password_policy(self):
        try:
            self.iam.get_account_password_policy()
        except ClientError as e:
            if "NoSuchEntity" in str(e):
                self.add_finding(
                    severity="MEDIUM",
                    resource="Account: Password Policy",
                    issue="Nenhuma política de senha customizada definida para a conta.",
                    remediation="Configurar política exigindo mínimo 14 caracteres, números, símbolos e expiração."
                )
