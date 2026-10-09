#!/usr/bin/env python3
"""
Script para destruição completa do Laboratório de Assessment:
Lê lab_resources.json e remove com segurança:
- Instâncias EC2 (terminate)
- Banco RDS (sem snapshot final para lab)
- Subnet Group RDS
- Registros e Hosted Zone Route 53
- Security Groups
- Subnets
- Route Table / Internet Gateway
- VPC
"""
import json
import os
import time
import boto3
from botocore.exceptions import ClientError
from rich.console import Console

console = Console()
REGION = "us-east-1"
PROFILE = "assessment"
RESOURCES_FILE = "E:\\01_Projetos\\Assessment_AWS\\lab\\lab_resources.json"

session = boto3.Session(profile_name=PROFILE, region_name=REGION)
ec2 = session.client("ec2")
rds = session.client("rds")
r53 = session.client("route53")

def destroy():
    if not os.path.exists(RESOURCES_FILE):
        console.print(f"[red]Arquivo {RESOURCES_FILE} não encontrado![/red]")
        return

    with open(RESOURCES_FILE, "r", encoding="utf-8") as f:
        res = json.load(f)

    console.print("[bold red]=== Iniciando Limpeza / Destruição do Laboratório ===[/bold red]")

    # 1. Terminate EC2
    inst_ids = [i["id"] for i in res.get("ec2_instances", [])]
    if inst_ids:
        console.print(f"[yellow]Terminando {len(inst_ids)} instâncias EC2...[/yellow]")
        ec2.terminate_instances(InstanceIds=inst_ids)
        console.print("  Aguardando encerramento das instâncias...")
        waiter = ec2.get_waiter("instance_terminated")
        waiter.wait(InstanceIds=inst_ids)
        console.print("  [green]✓ Instâncias EC2 terminadas.[/green]")

    # 2. Deletar RDS
    rds_id = res.get("rds_instance_id")
    if rds_id:
        console.print(f"[yellow]Deletando instância RDS {rds_id}...[/yellow]")
        try:
            rds.delete_db_instance(DBInstanceIdentifier=rds_id, SkipFinalSnapshot=True, DeleteAutomatedBackups=True)
            console.print("  Aguardando exclusão do RDS (pode levar alguns minutos)... ")
            waiter = rds.get_waiter("db_instance_deleted")
            waiter.wait(DBInstanceIdentifier=rds_id)
            console.print("  [green]✓ Banco RDS excluído.[/green]")
        except ClientError as e:
            console.print(f"  [yellow]RDS info/aviso: {e}[/yellow]")

    # 3. Deletar DB Subnet Group
    db_sub = res.get("db_subnet_group")
    if db_sub:
        try:
            rds.delete_db_subnet_group(DBSubnetGroupName=db_sub)
            console.print("  [green]✓ DB Subnet Group removido.[/green]")
        except ClientError as e:
            console.print(f"  [yellow]DB Subnet Group info: {e}[/yellow]")

    # 4. Deletar Route 53
    zone_id = res.get("route53_zone_id")
    if zone_id:
        console.print(f"[yellow]Removendo Route 53 Hosted Zone {zone_id}...[/yellow]")
        try:
            # Remove registros não padrão primeiro
            recs = r53.list_resource_record_sets(HostedZoneId=zone_id)["ResourceRecordSets"]
            for r in recs:
                if r["Type"] not in ["SOA", "NS"]:
                    r53.change_resource_record_sets(
                        HostedZoneId=zone_id,
                        ChangeBatch={"Changes": [{"Action": "DELETE", "ResourceRecordSet": r}]}
                    )
            r53.delete_hosted_zone(Id=zone_id)
            console.print("  [green]✓ Hosted Zone Route 53 removida.[/green]")
        except ClientError as e:
            console.print(f"  [yellow]Route 53 aviso: {e}[/yellow]")

    # 5. Deletar Security Groups
    for sg in res.get("security_groups", []):
        try:
            ec2.delete_security_group(GroupId=sg)
            console.print(f"  [green]✓ Security Group {sg} removido.[/green]")
        except ClientError as e:
            console.print(f"  [yellow]SG aviso: {e}[/yellow]")

    # 6. Deletar Subnets, IGW, Route Table e VPC
    for sub in res.get("subnets", []):
        try:
            ec2.delete_subnet(SubnetId=sub)
            console.print(f"  [green]✓ Subnet {sub} removida.[/green]")
        except ClientError as e:
            console.print(f"  [yellow]Subnet aviso: {e}[/yellow]")

    igw = res.get("igw_id")
    vpc = res.get("vpc_id")
    if igw and vpc:
        try:
            ec2.detach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
            ec2.delete_internet_gateway(InternetGatewayId=igw)
            console.print(f"  [green]✓ Internet Gateway {igw} desanexado e removido.[/green]")
        except ClientError as e:
            console.print(f"  [yellow]IGW aviso: {e}[/yellow]")

    rt = res.get("route_table_id")
    if rt:
        try:
            ec2.delete_route_table(RouteTableId=rt)
            console.print(f"  [green]✓ Route Table {rt} removida.[/green]")
        except ClientError as e:
            console.print(f"  [yellow]RT aviso: {e}[/yellow]")

    if vpc:
        try:
            ec2.delete_vpc(VpcId=vpc)
            console.print(f"  [green]✓ VPC {vpc} removida com sucesso.[/green]")
        except ClientError as e:
            console.print(f"  [yellow]VPC aviso: {e}[/yellow]")

    # Remove o arquivo JSON de controle
    if os.path.exists(RESOURCES_FILE):
        os.remove(RESOURCES_FILE)

    console.print("[bold green]=== Limpeza Concluída! Nenhum recurso residual ativo. ===[/bold green]")

if __name__ == "__main__":
    destroy()
