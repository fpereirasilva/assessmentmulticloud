"""
Gerenciador de sessões AWS com suporte a:
- Perfis locais (~/.aws/credentials)
- Variáveis de ambiente
- Cross-Account AssumeRole (permite auditar qualquer conta de cliente via Role)
"""
import boto3
from botocore.exceptions import ClientError
from rich.console import Console

console = Console()

class AWSSessionManager:
    def __init__(self, profile: str = None, region: str = "us-east-1"):
        self.profile = profile
        self.region = region
        self.base_session = boto3.Session(profile_name=profile, region_name=region)
        self.account_id = None
        self.account_arn = None
        self._identify()

    def _identify(self):
        """Obtém a identidade atual (Caller Identity)."""
        sts = self.base_session.client("sts")
        identity = sts.get_caller_identity()
        self.account_id = identity["Account"]
        self.account_arn = identity["Arn"]

    def get_session(self) -> boto3.Session:
        return self.base_session

    def get_client(self, service_name: str, region: str = None):
        reg = region or self.region
        return self.base_session.client(service_name, region_name=reg)

    def assume_role(self, role_arn: str, session_name: str = "AssessmentSession", external_id: str = None) -> boto3.Session:
        """
        Assume uma IAM Role em outra conta AWS (Cross-Account Assessment).
        Retorna uma nova sessão autenticada na conta de destino.
        """
        sts = self.base_session.client("sts")
        kwargs = {
            "RoleArn": role_arn,
            "RoleSessionName": session_name,
            "DurationSeconds": 3600,
        }
        if external_id:
            kwargs["ExternalId"] = external_id

        response = sts.assume_role(**kwargs)
        creds = response["Credentials"]

        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name=self.region
        )

    def get_all_regions(self, service: str = "ec2") -> list:
        """Retorna lista de todas as regiões ativas na conta."""
        try:
            ec2 = self.get_client("ec2")
            regions = ec2.describe_regions(AllRegions=False)["Regions"]
            return [r["RegionName"] for r in regions]
        except ClientError as e:
            console.print(f"[yellow]Aviso ao listar regiões: {e}[/yellow]")
            return [self.region]
