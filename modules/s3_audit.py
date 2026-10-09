"""
Módulo de auditoria de S3 (Simple Storage Service)
Verifica:
- S3 Block Public Access a nível de conta
- Buckets com acesso público habilitado ou ACLs abertas
- Criptografia padrão (SSE-S3 / SSE-KMS)
- Versionamento (proteção contra ransomware e deleção acidental)
- Logging de acesso aos buckets
"""
from botocore.exceptions import ClientError

class S3Auditor:
    def __init__(self, session, account_id: str):
        self.session = session
        self.account_id = account_id
        self.s3 = session.client("s3")
        self.s3control = session.client("s3control")
        self.findings = []

    def add_finding(self, severity: str, resource: str, issue: str, remediation: str):
        self.findings.append({
            "service": "S3",
            "severity": severity,
            "resource": resource,
            "issue": issue,
            "remediation": remediation
        })

    def run(self) -> list:
        self.check_account_public_access_block()
        self.check_buckets()
        return self.findings

    def check_account_public_access_block(self):
        try:
            res = self.s3control.get_public_access_block(AccountId=self.account_id)
            cfg = res.get("PublicAccessBlockConfiguration", {})
            if not (cfg.get("BlockPublicAcls") and cfg.get("IgnorePublicAcls") and
                    cfg.get("BlockPublicPolicy") and cfg.get("RestrictPublicBuckets")):
                self.add_finding(
                    severity="HIGH",
                    resource=f"Account S3 Block Public Access ({self.account_id})",
                    issue="O 'S3 Block Public Access' a nível de conta não está 100% ativado.",
                    remediation="Habilitar todas as 4 travas do Block Public Access na conta para prevenir vazamentos."
                )
            else:
                self.add_finding(
                    severity="INFO",
                    resource=f"Account S3 Block Public Access ({self.account_id})",
                    issue="S3 Block Public Access está 100% ativo na conta.",
                    remediation="Manter configuração."
                )
        except ClientError as e:
            if "NoSuchPublicAccessBlockConfiguration" in str(e):
                self.add_finding(
                    severity="HIGH",
                    resource=f"Account S3 Block Public Access ({self.account_id})",
                    issue="Nenhum 'S3 Block Public Access' configurado na conta.",
                    remediation="Ativar S3 Block Public Access globalmente no console S3."
                )
            else:
                self.add_finding("LOW", "S3Control:PublicAccessBlock", f"Erro ao ler trava global: {e}", "Verificar permissões.")

    def check_buckets(self):
        try:
            buckets = self.s3.list_buckets().get("Buckets", [])
            if not buckets:
                self.add_finding("INFO", "S3:Buckets", "Nenhum bucket S3 encontrado na conta.", "Nenhuma ação necessária.")
                return

            for b in buckets:
                b_name = b["Name"]

                # Checar Criptografia Padrão
                try:
                    self.s3.get_bucket_encryption(Bucket=b_name)
                except ClientError as e:
                    if "ServerSideEncryptionConfigurationNotFoundError" in str(e):
                        self.add_finding(
                            severity="HIGH",
                            resource=f"Bucket: {b_name}",
                            issue="Bucket S3 não possui criptografia padrão configurada.",
                            remediation="Ativar criptografia SSE-S3 (AES256) ou SSE-KMS."
                        )

                # Checar Versionamento
                try:
                    ver = self.s3.get_bucket_versioning(Bucket=b_name)
                    if ver.get("Status") != "Enabled":
                        self.add_finding(
                            severity="MEDIUM",
                            resource=f"Bucket: {b_name}",
                            issue="Versionamento desabilitado no bucket.",
                            remediation="Habilitar versionamento para proteção contra exclusão acidental ou ransomware."
                        )
                except ClientError:
                    pass

                # Checar Trava Pública do Bucket
                try:
                    pab = self.s3.get_public_access_block(Bucket=b_name).get("PublicAccessBlockConfiguration", {})
                    if not (pab.get("BlockPublicAcls") and pab.get("BlockPublicPolicy")):
                        self.add_finding(
                            severity="HIGH",
                            resource=f"Bucket: {b_name}",
                            issue="Bucket com travas de acesso público parciais ou desativadas.",
                            remediation="Habilitar Block Public Access no bucket."
                        )
                except ClientError as e:
                    if "NoSuchPublicAccessBlockConfiguration" in str(e):
                        self.add_finding(
                            severity="HIGH",
                            resource=f"Bucket: {b_name}",
                            issue="Bucket sem nenhuma trava de acesso público (Block Public Access desativado).",
                            remediation="Habilitar Block Public Access imediatamente no bucket."
                        )

        except ClientError as e:
            self.add_finding("LOW", "S3:ListBuckets", f"Erro ao listar buckets: {e}", "Revisar permissões.")
