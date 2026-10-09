#!/usr/bin/env python3
"""
CLI Principal de Assessment AWS Multi-Conta:
Executa auditoria completa ou por módulos e gera relatórios.
Suporta: perfil local, variável de ambiente ou Cross-Account AssumeRole.
"""
import argparse
import sys
from rich.console import Console
from rich.panel import Panel

from core.session_manager import AWSSessionManager
from core.report_generator import ReportGenerator
from modules.iam_audit import IAMAuditor
from modules.s3_audit import S3Auditor
from modules.network_audit import NetworkAuditor
from modules.compute_audit import ComputeAuditor
from modules.database_audit import DatabaseAuditor
from modules.dns_audit import DNSAuditor

console = Console()

def main():
    parser = argparse.ArgumentParser(description="AWS Well-Architected & Security Assessment Tool")
    parser.add_argument("--profile", help="Nome do perfil AWS (ex: assessment ou default)", default="assessment")
    parser.add_argument("--region", help="Região base da AWS (padrão: us-east-1)", default="us-east-1")
    parser.add_argument("--role-arn", help="ARN da IAM Role para Cross-Account AssumeRole", default=None)
    parser.add_argument("--external-id", help="External ID opcional para AssumeRole", default=None)
    parser.add_argument("--all-regions", action="store_true", help="Varre todas as regiões ativas da conta")
    parser.add_argument("--module", choices=["all", "iam", "s3", "network", "compute", "database", "dns"], default="all", help="Módulo específico para rodar")
    args = parser.parse_args()

    console.print(Panel.fit("[bold cyan]AWS Infrastructure Assessment & Well-Architected Framework[/bold cyan]", border_style="cyan"))

    # 1. Inicia Sessão
    try:
        mgr = AWSSessionManager(profile=args.profile, region=args.region)
    except Exception as e:
        console.print(f"[bold red]Erro ao inicializar sessão AWS:[/bold red] {e}")
        sys.exit(1)

    # 2. AssumeRole se fornecido (Cross-Account)
    target_session = mgr.get_session()
    target_account = mgr.account_id
    target_arn = mgr.account_arn

    if args.role_arn:
        console.print(f"[yellow]Assumindo Cross-Account Role:[/yellow] {args.role_arn}")
        try:
            target_session = mgr.assume_role(role_arn=args.role_arn, external_id=args.external_id)
            sts = target_session.client("sts")
            ident = sts.get_caller_identity()
            target_account = ident["Account"]
            target_arn = ident["Arn"]
            console.print(f"[green]✓ Conectado na conta de destino:[/green] {target_account}")
        except Exception as e:
            console.print(f"[bold red]Falha no AssumeRole:[/bold red] {e}")
            sys.exit(1)

    console.print(f"[bold]Conta Alvo:[/bold] [yellow]{target_account}[/yellow] | [bold]Identidade:[/bold] [dim]{target_arn}[/dim] | [bold]Região Base:[/bold] [cyan]{args.region}[/cyan]\n")

    # Determina regiões de escopo
    regions = [args.region]
    if args.all_regions:
        console.print("[dim]Descobrindo todas as regiões ativas na conta...[/dim]")
        regions = mgr.get_all_regions()
        console.print(f"[dim]Varredura configurada para {len(regions)} regiões.[/dim]\n")

    all_findings = []

    # 3. Execução dos Módulos
    if args.module in ["all", "iam"]:
        console.print("[bold blue]➔ Auditando IAM (Identidade, Acessos, MFA)...[/bold blue]")
        iam_audit = IAMAuditor(session=target_session)
        f_iam = iam_audit.run()
        all_findings.extend(f_iam)
        console.print(f"   [green]✓ IAM concluído:[/green] {len(f_iam)} apontamento(s)")

    if args.module in ["all", "s3"]:
        console.print("[bold blue]➔ Auditando S3 (Armazenamento, Bloqueio Público, Criptografia)...[/bold blue]")
        s3_audit = S3Auditor(session=target_session, account_id=target_account)
        f_s3 = s3_audit.run()
        all_findings.extend(f_s3)
        console.print(f"   [green]✓ S3 concluído:[/green] {len(f_s3)} apontamento(s)")

    if args.module in ["all", "network"]:
        console.print("[bold blue]➔ Auditando Rede (VPC, Security Groups, Portas Abertas)...[/bold blue]")
        net_audit = NetworkAuditor(session=target_session, regions=regions)
        f_net = net_audit.run()
        all_findings.extend(f_net)
        console.print(f"   [green]✓ Rede concluída:[/green] {len(f_net)} apontamento(s)")

    if args.module in ["all", "compute"]:
        console.print("[bold blue]➔ Auditando Computação e Discos (EC2, IMDSv2, EBS gp2/gp3)...[/bold blue]")
        comp_audit = ComputeAuditor(session=target_session, regions=regions)
        f_comp = comp_audit.run()
        all_findings.extend(f_comp)
        console.print(f"   [green]✓ EC2/EBS concluído:[/green] {len(f_comp)} apontamento(s)")

    if args.module in ["all", "database"]:
        console.print("[bold blue]➔ Auditando Banco de Dados (RDS, Multi-AZ, Criptografia, Backup)...[/bold blue]")
        db_audit = DatabaseAuditor(session=target_session, regions=regions)
        f_db = db_audit.run()
        all_findings.extend(f_db)
        console.print(f"   [green]✓ RDS concluído:[/green] {len(f_db)} apontamento(s)")

    if args.module in ["all", "dns"]:
        console.print("[bold blue]➔ Auditando DNS (Route 53, Zonas, DNSSEC, Logging)...[/bold blue]")
        dns_audit = DNSAuditor(session=target_session)
        f_dns = dns_audit.run()
        all_findings.extend(f_dns)
        console.print(f"   [green]✓ Route 53 concluído:[/green] {len(f_dns)} apontamento(s)")

    console.print("\n[bold green]=== Varredura Finalizada! ===[/bold green]\n")

    # 4. Geração de Relatórios
    rep = ReportGenerator(account_id=target_account, account_arn=target_arn, findings=all_findings)
    rep.print_terminal_summary()

    html_path = rep.generate_html_landscape()
    md_path = rep.generate_markdown()
    json_path = rep.generate_json()

    console.print(f"\n[bold green]Relatórios SoftwareOne gerados com sucesso:[/bold green]")
    console.print(f"  [bold cyan]🖥️ HTML Landscape (Paisagem/PDF):[/bold cyan] {html_path}")
    console.print(f"  [cyan]📄 Markdown:[/cyan] {md_path}")
    console.print(f"  [cyan]📊 JSON:    [/cyan] {json_path}\n")

if __name__ == "__main__":
    main()
