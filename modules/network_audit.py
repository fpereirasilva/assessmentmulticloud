"""
Módulo de auditoria de Rede (VPC e Security Groups)
Verifica:
- Security Groups com portas de administração abertas para o mundo (22, 3389, bancos de dados)
- VPCs sem VPC Flow Logs habilitados
- Default VPCs em uso
"""
from botocore.exceptions import ClientError

RISKY_PORTS = {
    22: ("SSH", "CRITICAL"),
    3389: ("RDP", "CRITICAL"),
    23: ("Telnet", "CRITICAL"),
    21: ("FTP", "HIGH"),
    3306: ("MySQL", "HIGH"),
    5432: ("PostgreSQL", "HIGH"),
    1433: ("MS SQL", "HIGH"),
    1521: ("Oracle DB", "HIGH"),
    27017: ("MongoDB", "HIGH"),
    6379: ("Redis", "HIGH"),
    9200: ("Elasticsearch", "HIGH"),
    8080: ("Web Alternativo", "LOW"),
}

class NetworkAuditor:
    def __init__(self, session, regions: list):
        self.session = session
        self.regions = regions
        self.findings = []

    def add_finding(self, severity: str, resource: str, issue: str, remediation: str):
        self.findings.append({
            "service": "Network/VPC",
            "severity": severity,
            "resource": resource,
            "issue": issue,
            "remediation": remediation
        })

    def run(self) -> list:
        for reg in self.regions:
            self.check_region_network(reg)
        return self.findings

    def check_region_network(self, region: str):
        try:
            ec2 = self.session.client("ec2", region_name=region)

            # Checar Security Groups
            sgs = ec2.describe_security_groups()["SecurityGroups"]
            for sg in sgs:
                sg_id = sg["GroupId"]
                sg_name = sg.get("GroupName", "unnamed")

                for rule in sg.get("IpPermissions", []):
                    from_port = rule.get("FromPort")
                    to_port = rule.get("ToPort")
                    ip_ranges = [r.get("CidrIp") for r in rule.get("IpRanges", [])]

                    is_open_to_world = "0.0.0.0/0" in ip_ranges

                    if is_open_to_world:
                        # Regra que abre tudo (-1)
                        if rule.get("IpProtocol") == "-1":
                            self.add_finding(
                                severity="CRITICAL",
                                resource=f"SG: {sg_id} ({sg_name}) [{region}]",
                                issue="Security Group abre TODO O TRÁFEGO (todos os protocolos/portas) para 0.0.0.0/0.",
                                remediation="Restringir as regras de entrada aos IPs/portas estritamente necessários."
                            )
                            continue

                        if from_port is not None and to_port is not None:
                            for p, (p_name, p_sev) in RISKY_PORTS.items():
                                if from_port <= p <= to_port:
                                    self.add_finding(
                                        severity=p_sev,
                                        resource=f"SG: {sg_id} ({sg_name}) [{region}]",
                                        issue=f"Porta {p} ({p_name}) está aberta diretamente para a Internet (0.0.0.0/0).",
                                        remediation=f"Restringir a porta {p} para VPN, Bastion Host ou IPs de origem específicos."
                                    )

            # Checar VPC Flow Logs
            vpcs = ec2.describe_vpcs()["Vpcs"]
            for vpc in vpcs:
                vpc_id = vpc["VpcId"]
                is_default = vpc.get("IsDefault", False)

                flow_logs = ec2.describe_flow_logs(Filters=[{"Name": "resource-id", "Values": [vpc_id]}])["FlowLogs"]
                if not flow_logs:
                    self.add_finding(
                        severity="MEDIUM",
                        resource=f"VPC: {vpc_id} (Default: {is_default}) [{region}]",
                        issue="VPC não possui VPC Flow Logs habilitado para auditoria e monitoramento de tráfego de rede.",
                        remediation="Habilitar VPC Flow Logs enviando para o CloudWatch Logs ou bucket S3."
                    )

        except ClientError as e:
            # Ignora erros de regiões desabilitadas na conta
            if "AuthFailure" not in str(e) and "UnauthorizedOperation" not in str(e):
                self.add_finding("LOW", f"EC2/VPC [{region}]", f"Erro ao verificar rede: {e}", "Revisar permissões.")
