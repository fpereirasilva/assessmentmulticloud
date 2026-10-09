"""
Módulo de auditoria de Computação e Armazenamento (EC2 e EBS)
Verifica:
- Instâncias usando IMDSv1 (risco de sequestro de credenciais via SSRF)
- Volumes EBS sem criptografia KMS/padrão
- Volumes gp2 antigos (recomendação de melhoria: migrar para gp3 gera economia de 20% e mais IOPS)
- Volumes desanexados (órfãos gerando custo desnecessário)
- Detecção de instâncias sem tags obrigatórias (Environment, Owner, Project)
"""
from botocore.exceptions import ClientError

class ComputeAuditor:
    def __init__(self, session, regions: list):
        self.session = session
        self.regions = regions
        self.findings = []

    def add_finding(self, severity: str, resource: str, issue: str, remediation: str, category: str = "Security"):
        self.findings.append({
            "service": "EC2/EBS",
            "category": category,  # Security, Cost, Performance, Reliability
            "severity": severity,
            "resource": resource,
            "issue": issue,
            "remediation": remediation
        })

    def run(self) -> list:
        for reg in self.regions:
            self.check_region_compute(reg)
        return self.findings

    def check_region_compute(self, region: str):
        try:
            ec2 = self.session.client("ec2", region_name=region)

            # 1. Auditoria de Instâncias EC2
            res = ec2.describe_instances()
            for resv in res.get("Reservations", []):
                for inst in resv.get("Instances", []):
                    inst_id = inst["InstanceId"]
                    name_tag = next((t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"), "unnamed")
                    state = inst.get("State", {}).get("Name")
                    inst_type = inst.get("InstanceType")

                    # IMDSv1 vs IMDSv2
                    meta_opts = inst.get("MetadataOptions", {})
                    http_tokens = meta_opts.get("HttpTokens")
                    if http_tokens != "required":
                        self.add_finding(
                            severity="HIGH",
                            resource=f"EC2: {inst_id} ({name_tag}) [{region}]",
                            issue="Instância permite IMDSv1 (Tokens de metadados opcionais), vulnerável a ataques de SSRF.",
                            remediation="Configurar 'HttpTokens=required' para forçar IMDSv2 em todas as instâncias.",
                            category="Security"
                        )

                    # Oportunidade de Custo/Performance: Instâncias antigas (t2 -> t3 ou t4g ARM)
                    if inst_type.startswith("t2."):
                        self.add_finding(
                            severity="LOW",
                            resource=f"EC2: {inst_id} ({name_tag}) [{region}]",
                            issue=f"Instância usa família de geração antiga ({inst_type}).",
                            remediation="Migrar para t3 (Intel/AMD) ou t4g (Graviton ARM) para melhor performance e até 20% menor custo.",
                            category="Cost & Performance"
                        )

                    # Falta de Tags de Governança
                    tag_keys = [t["Key"].lower() for t in inst.get("Tags", [])]
                    required_tags = ["environment", "project", "owner"]
                    missing = [t for t in required_tags if t not in tag_keys]
                    if missing:
                        self.add_finding(
                            severity="LOW",
                            resource=f"EC2: {inst_id} ({name_tag}) [{region}]",
                            issue=f"Instância sem tags de governança recomendadas: {', '.join(missing)}.",
                            remediation="Adicionar tags padronizadas para alocação de custos e rastreabilidade.",
                            category="Governance"
                        )

            # 2. Auditoria de Volumes EBS
            vols = ec2.describe_volumes().get("Volumes", [])
            for vol in vols:
                vol_id = vol["VolumeId"]
                vol_type = vol.get("VolumeType")
                size_gb = vol.get("Size")
                encrypted = vol.get("Encrypted", False)
                attachments = vol.get("Attachments", [])

                # Criptografia
                if not encrypted:
                    self.add_finding(
                        severity="HIGH",
                        resource=f"EBS: {vol_id} ({size_gb}GB) [{region}]",
                        issue="Volume EBS não está criptografado em repouso (at-rest).",
                        remediation="Habilitar criptografia padrão na conta e criptografar volumes via snapshot/KMS.",
                        category="Security"
                    )

                # Melhoria de Custo & Performance (gp2 -> gp3)
                if vol_type == "gp2":
                    self.add_finding(
                        severity="MEDIUM",
                        resource=f"EBS: {vol_id} ({size_gb}GB, gp2) [{region}]",
                        issue="Volume utiliza tipo legado 'gp2'. O tipo 'gp3' oferece 3000 IOPS de base e custa 20% menos.",
                        remediation="Modificar tipo do volume de gp2 para gp3 via Elastic Volumes sem downtime.",
                        category="Cost & Performance"
                    )

                # Volume Órfão / Desanexado
                if not attachments:
                    self.add_finding(
                        severity="MEDIUM",
                        resource=f"EBS: {vol_id} ({size_gb}GB) [{region}]",
                        issue="Volume EBS desanexado (órfão) gerando custo desnecessário.",
                        remediation="Verificar se o dado ainda é necessário, tirar snapshot de segurança e deletar o volume.",
                        category="Cost"
                    )

        except ClientError as e:
            if "AuthFailure" not in str(e) and "UnauthorizedOperation" not in str(e):
                self.add_finding("LOW", f"EC2/EBS [{region}]", f"Erro ao ler computação: {e}", "Revisar permissões.")
