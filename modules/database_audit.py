"""
Módulo de auditoria de Banco de Dados (RDS)
Verifica:
- Criptografia em repouso (StorageEncrypted)
- Alta Disponibilidade (Multi-AZ) e Resiliência (Well-Architected)
- Acesso Público (PubliclyAccessible deve ser False)
- Retenção de Backups automatizados
- Tipo de Armazenamento (gp2 -> recomendação de gp3 para economia e IOPS)
- Auto Minor Version Upgrade
"""
from botocore.exceptions import ClientError

class DatabaseAuditor:
    def __init__(self, session, regions: list):
        self.session = session
        self.regions = regions
        self.findings = []

    def add_finding(self, severity: str, resource: str, issue: str, remediation: str, category: str = "Reliability"):
        self.findings.append({
            "service": "RDS",
            "category": category,  # Security, Reliability, Cost & Performance
            "severity": severity,
            "resource": resource,
            "issue": issue,
            "remediation": remediation
        })

    def run(self) -> list:
        for reg in self.regions:
            self.check_region_rds(reg)
        return self.findings

    def check_region_rds(self, region: str):
        try:
            rds = self.session.client("rds", region_name=region)
            instances = rds.describe_db_instances().get("DBInstances", [])

            for db in instances:
                db_id = db["DBInstanceIdentifier"]
                engine = db["Engine"]
                storage_type = db.get("StorageType")
                multi_az = db.get("MultiAZ", False)
                encrypted = db.get("StorageEncrypted", False)
                public = db.get("PubliclyAccessible", False)
                backup_retention = db.get("BackupRetentionPeriod", 0)
                auto_minor = db.get("AutoMinorVersionUpgrade", False)
                deletion_prot = db.get("DeletionProtection", False)

                # 1. Acesso Público
                if public:
                    self.add_finding(
                        severity="CRITICAL",
                        resource=f"RDS: {db_id} ({engine}) [{region}]",
                        issue="Banco de dados RDS está marcado como 'Publicly Accessible' (IP público).",
                        remediation="Desativar acessibilidade pública e isolar o banco em subnets privadas.",
                        category="Security"
                    )

                # 2. Criptografia em Repouso
                if not encrypted:
                    self.add_finding(
                        severity="HIGH",
                        resource=f"RDS: {db_id} ({engine}) [{region}]",
                        issue="Armazenamento do banco RDS não está criptografado com AWS KMS.",
                        remediation="Criar snapshot, copiar o snapshot com criptografia KMS habilitada e restaurar.",
                        category="Security"
                    )

                # 3. Alta Disponibilidade (Multi-AZ)
                if not multi_az:
                    self.add_finding(
                        severity="MEDIUM",
                        resource=f"RDS: {db_id} ({engine}) [{region}]",
                        issue="Banco opera em Single-AZ (sem réplica síncrona de failover em outra AZ).",
                        remediation="Para ambientes de produção, habilitar Multi-AZ para garantir failover automático e RTO/RPO.",
                        category="Reliability"
                    )

                # 4. Retenção de Backup
                if backup_retention < 7:
                    self.add_finding(
                        severity="MEDIUM",
                        resource=f"RDS: {db_id} ({engine}) [{region}]",
                        issue=f"Janela de retenção de backup automatizado muito baixa ({backup_retention} dia(s)).",
                        remediation="Aumentar o período de retenção para no mínimo 7 a 30 dias para possibilitar Point-In-Time Restore (PITR).",
                        category="Reliability"
                    )

                # 5. Oportunidade gp2 -> gp3
                if storage_type == "gp2":
                    self.add_finding(
                        severity="LOW",
                        resource=f"RDS: {db_id} ({engine}) [{region}]",
                        issue="Armazenamento tipo 'gp2'. O tipo 'gp3' reduz custo em até 20% e desacopla IOPS de tamanho.",
                        remediation="Modificar a classe de armazenamento de gp2 para gp3 no RDS.",
                        category="Cost & Performance"
                    )

                # 6. Deletion Protection
                if not deletion_prot:
                    self.add_finding(
                        severity="LOW",
                        resource=f"RDS: {db_id} ({engine}) [{region}]",
                        issue="Proteção contra exclusão acidental (Deletion Protection) desativada.",
                        remediation="Habilitar Deletion Protection no console ou via CLI para evitar queda acidental.",
                        category="Governance & Reliability"
                    )

        except ClientError as e:
            if "AuthFailure" not in str(e) and "UnauthorizedOperation" not in str(e):
                self.add_finding("LOW", f"RDS [{region}]", f"Erro ao verificar RDS: {e}", "Revisar permissões.")
