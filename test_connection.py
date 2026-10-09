#!/usr/bin/env python3
"""
Script para testar autenticação e conectividade com a AWS.
Suporta perfis nomeados (ex: --profile assessment) ou variáveis de ambiente.
"""
import argparse
import sys
import boto3
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

def test_aws_auth(profile: str = None, region: str = "us-east-1"):
    try:
        session_kwargs = {}
        if profile:
            session_kwargs["profile_name"] = profile
        if region:
            session_kwargs["region_name"] = region

        session = boto3.Session(**session_kwargs)
        sts = session.client("sts")
        identity = sts.get_caller_identity()

        table = Table(title="[bold green]AWS Authentication Successful[/bold green]")
        table.add_column("Propriedade", style="cyan", no_wrap=True)
        table.add_column("Valor", style="yellow")

        table.add_row("Account ID", identity.get("Account"))
        table.add_row("User / Role ARN", identity.get("Arn"))
        table.add_row("User ID", identity.get("UserId"))
        table.add_row("Região Ativa", session.region_name or "us-east-1")
        table.add_row("Perfil Usado", profile or "default (ou env vars)")

        console.print(table)

        # Tenta listar regiões para validar se tem permissão básica
        ec2 = session.client("ec2")
        try:
            regions = [r["RegionName"] for r in ec2.describe_regions()["Regions"]]
            console.print(f"\n[dim]Regiões EC2 disponíveis: {len(regions)} regiões detectadas.[/dim]")
        except Exception:
            console.print("[dim yellow]Aviso: Sem permissão para ec2:DescribeRegions (esperado se a chave for restrita).[/dim yellow]")

        return True

    except NoCredentialsError:
        console.print(Panel("[bold red]Nenhuma credencial AWS encontrada![/bold red]\n\nConfigure via:\n1. `aws configure` (ou `aws configure --profile <nome>`)\n2. Ou exporte AWS_ACCESS_KEY_ID e AWS_SECRET_ACCESS_KEY", title="Erro de Autenticação"))
        return False
    except ProfileNotFound as e:
        console.print(f"[bold red]Perfil não encontrado:[/bold red] {e}")
        return False
    except ClientError as e:
        console.print(f"[bold red]Erro de API AWS:[/bold red] {e}")
        return False
    except Exception as e:
        console.print(f"[bold red]Erro inesperado:[/bold red] {e}")
        return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Testa conexão e identidade com AWS")
    parser.add_argument("--profile", help="Nome do perfil no ~/.aws/credentials (ex: assessment)", default=None)
    parser.add_argument("--region", help="Região AWS (padrão: us-east-1)", default="us-east-1")
    args = parser.parse_args()

    success = test_aws_auth(profile=args.profile, region=args.region)
    sys.exit(0 if success else 1)
