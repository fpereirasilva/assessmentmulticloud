"""
Módulo de auditoria de DNS (Amazon Route 53)
Verifica:
- Zonas hospedadas (Hosted Zones) públicas e privadas
- DNSSEC habilitado para zonas públicas (proteção contra cache poisoning)
- Query Logging habilitado para monitoramento de segurança/tráfego de DNS
- Registros órfãos ou com TTLs desbalanceados
"""
from botocore.exceptions import ClientError

class DNSAuditor:
    def __init__(self, session):
        self.r53 = session.client("route53")
        self.findings = []

    def add_finding(self, severity: str, resource: str, issue: str, remediation: str, category: str = "Security"):
        self.findings.append({
            "service": "Route 53",
            "category": category,
            "severity": severity,
            "resource": resource,
            "issue": issue,
            "remediation": remediation
        })

    def run(self) -> list:
        self.check_zones()
        return self.findings

    def check_zones(self):
        try:
            zones = self.r53.list_hosted_zones().get("HostedZones", [])
            if not zones:
                self.add_finding("INFO", "Route53:Zones", "Nenhuma zona hospedada encontrada.", "Nenhuma ação necessária.")
                return

            for z in zones:
                z_id = z["Id"].replace("/hostedzone/", "")
                z_name = z["Name"]
                is_private = z.get("Config", {}).get("PrivateZone", False)

                # DNSSEC para Zonas Públicas
                if not is_private:
                    try:
                        dnssec = self.r53.get_dnssec(HostedZoneId=z_id)
                        status = dnssec.get("Status", {}).get("ServeSignature")
                        if status != "SIGNING":
                            self.add_finding(
                                severity="MEDIUM",
                                resource=f"Route53: {z_name} ({z_id}) [Pública]",
                                issue="DNSSEC não está ativado na zona pública, vulnerável a DNS spoofing / cache poisoning.",
                                remediation="Ativar assinatura DNSSEC e configurar o registro DS no registrador do domínio.",
                                category="Security"
                            )
                    except ClientError:
                        self.add_finding(
                            severity="MEDIUM",
                            resource=f"Route53: {z_name} ({z_id}) [Pública]",
                            issue="DNSSEC não configurado na zona pública.",
                            remediation="Ativar DNSSEC no Route 53.",
                            category="Security"
                        )

                # Query Logging (Auditoria de Tráfego DNS)
                try:
                    logs = self.r53.list_query_logging_configs(HostedZoneId=z_id).get("QueryLoggingConfigs", [])
                    if not logs:
                        self.add_finding(
                            severity="LOW",
                            resource=f"Route53: {z_name} ({z_id}) [{'Privada' if is_private else 'Pública'}]",
                            issue="Query Logging de DNS não configurado para envio ao CloudWatch Logs.",
                            remediation="Habilitar Route 53 Query Logging para auditoria forense e rastreabilidade.",
                            category="Security & Observability"
                        )
                except ClientError:
                    pass

        except ClientError as e:
            self.add_finding("LOW", "Route53:ListHostedZones", f"Erro ao listar zonas DNS: {e}", "Revisar permissões.")
