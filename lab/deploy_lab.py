#!/usr/bin/env python3
"""
Script para deploy do Laboratório de Assessment na AWS:
- 1 VPC + 2 Subnets (us-east-1a e us-east-1b) + Internet Gateway
- 2 Security Groups (Web com SSH/HTTP aberto propositalmente para teste de auditoria, e DB)
- 5 Instâncias EC2 t3.micro (Ubuntu 24, Amazon Linux 2023, Debian 12, Win2022, RHEL 9)
- 1 Banco RDS PostgreSQL db.t3.micro (Single-AZ, 20GB gp2)
- 1 Hosted Zone Route 53 privada (lab.corp.internal) com records A e CNAME
- Salva os IDs criados em lab_resources.json para deleção facilitada
"""
import json
import time
import boto3
from botocore.exceptions import ClientError
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()
REGION = "us-east-1"
PROFILE = "assessment"

session = boto3.Session(profile_name=PROFILE, region_name=REGION)
ec2 = session.client("ec2")
rds = session.client("rds")
r53 = session.client("route53")

AMIS = {
    "lab-web-frontend": {"ami": "ami-0fa5967347d08d2df", "os": "Ubuntu 24.04 LTS", "role": "Frontend Web Server"},
    "lab-app-backend": {"ami": "ami-0d27e0fb3bac4d724", "os": "Amazon Linux 2023", "role": "Backend API"},
    "lab-database-cache": {"ami": "ami-0dc94268e09c4cabe", "os": "Debian 12", "role": "Database / Cache"},
    "lab-bastion-win": {"ami": "ami-0ed58a129008c2cc2", "os": "Windows Server 2022", "role": "Bastion Host / Admin"},
    "lab-legacy-service": {"ami": "ami-0b07d2bc8152a1d84", "os": "RHEL 9", "role": "Legacy Enterprise App"}
}

def deploy():
    resources = {"region": REGION, "ec2_instances": [], "security_groups": [], "subnets": []}
    console.print("[bold cyan]=== Iniciando Deploy do Laboratório de Assessment AWS ===[/bold cyan]")

    # 1. VPC
    console.print("\n[yellow][1/6] Criando VPC de Laboratório...[/yellow]")
    vpc = ec2.create_vpc(CidrBlock="10.50.0.0/16")["Vpc"]
    vpc_id = vpc["VpcId"]
    resources["vpc_id"] = vpc_id
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "Name", "Value": "vpc-assessment-lab"}, {"Key": "Environment", "Value": "Lab"}])
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    console.print(f"  [green]✓ VPC criada:[/green] {vpc_id} (10.50.0.0/16)")

    # 2. Internet Gateway
    console.print("\n[yellow][2/6] Criando Internet Gateway e Route Table...[/yellow]")
    igw = ec2.create_internet_gateway()["InternetGateway"]
    igw_id = igw["InternetGatewayId"]
    resources["igw_id"] = igw_id
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ec2.create_tags(Resources=[igw_id], Tags=[{"Key": "Name", "Value": "igw-assessment-lab"}])

    rt = ec2.create_route_table(VpcId=vpc_id)["RouteTable"]
    rt_id = rt["RouteTableId"]
    resources["route_table_id"] = rt_id
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    console.print(f"  [green]✓ IGW criado e rota 0.0.0.0/0 associada:[/green] {igw_id}")

    # 3. Subnets (2 AZs para permitir RDS)
    console.print("\n[yellow][3/6] Criando Subnets em 2 Zonas de Disponibilidade...[/yellow]")
    sub1 = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.50.1.0/24", AvailabilityZone="us-east-1a")["Subnet"]
    sub1_id = sub1["SubnetId"]
    resources["subnets"].append(sub1_id)
    ec2.create_tags(Resources=[sub1_id], Tags=[{"Key": "Name", "Value": "subnet-assessment-public-1a"}])
    ec2.associate_route_table(SubnetId=sub1_id, RouteTableId=rt_id)
    ec2.modify_subnet_attribute(SubnetId=sub1_id, MapPublicIpOnLaunch={"Value": True})

    sub2 = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.50.2.0/24", AvailabilityZone="us-east-1b")["Subnet"]
    sub2_id = sub2["SubnetId"]
    resources["subnets"].append(sub2_id)
    ec2.create_tags(Resources=[sub2_id], Tags=[{"Key": "Name", "Value": "subnet-assessment-private-1b"}])
    ec2.associate_route_table(SubnetId=sub2_id, RouteTableId=rt_id)
    console.print(f"  [green]✓ Subnet 1a (Pública):[/green] {sub1_id}")
    console.print(f"  [green]✓ Subnet 1b (App/DB):[/green]  {sub2_id}")

    # 4. Security Groups
    console.print("\n[yellow][4/6] Configurando Security Groups...[/yellow]")
    # SG Web com regras propositais de teste (SSH e HTTP abertos)
    sg_web = ec2.create_security_group(
        GroupName="assessment-web-sg",
        Description="SG Web com portas expostas para teste de assessment",
        VpcId=vpc_id
    )["GroupId"]
    resources["security_groups"].append(sg_web)
    ec2.create_tags(Resources=[sg_web], Tags=[{"Key": "Name", "Value": "assessment-web-sg"}])
    ec2.authorize_security_group_ingress(
        GroupId=sg_web,
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
            {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}  # Descoberta de segurança!
        ]
    )

    # SG Database
    sg_db = ec2.create_security_group(
        GroupName="assessment-db-sg",
        Description="SG para o banco RDS",
        VpcId=vpc_id
    )["GroupId"]
    resources["security_groups"].append(sg_db)
    ec2.create_tags(Resources=[sg_db], Tags=[{"Key": "Name", "Value": "assessment-db-sg"}])
    ec2.authorize_security_group_ingress(
        GroupId=sg_db,
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432, "UserIdGroupPairs": [{"GroupId": sg_web}]}
        ]
    )
    console.print(f"  [green]✓ SG Web:[/green] {sg_web} (Portas 80, 443, 22 abertas para teste de auditoria)")
    console.print(f"  [green]✓ SG DB:[/green]  {sg_db} (Porta 5432 permitida do SG Web)")

    # 5. Criar as 5 Máquinas EC2
    console.print("\n[yellow][5/6] Subindo as 5 Máquinas EC2 (t3.micro)...[/yellow]")
    for name, info in AMIS.items():
        res = ec2.run_instances(
            ImageId=info["ami"],
            InstanceType="t3.micro",
            MinCount=1,
            MaxCount=1,
            SubnetId=sub1_id,
            SecurityGroupIds=[sg_web],
            TagSpecifications=[{
                "ResourceType": "instance",
                "Tags": [
                    {"Key": "Name", "Value": name},
                    {"Key": "OS", "Value": info["os"]},
                    {"Key": "Role", "Value": info["role"]},
                    {"Key": "Project", "Value": "Assessment-Lab"}
                ]
            }]
        )
        inst_id = res["Instances"][0]["InstanceId"]
        resources["ec2_instances"].append({"id": inst_id, "name": name, "os": info["os"]})
        console.print(f"  [green]✓ {name}[/green] ({info['os']}) -> [cyan]{inst_id}[/cyan]")

    # 6. Criar RDS PostgreSQL
    console.print("\n[yellow][6/6] Criando DB Subnet Group e Instância RDS PostgreSQL (db.t3.micro)...[/yellow]")
    db_sub_name = "dbsubnet-assessment-lab"
    try:
        rds.create_db_subnet_group(
            DBSubnetGroupName=db_sub_name,
            DBSubnetGroupDescription="Subnet group para RDS lab",
            SubnetIds=[sub1_id, sub2_id]
        )
        resources["db_subnet_group"] = db_sub_name
        console.print(f"  [green]✓ DB Subnet Group criado:[/green] {db_sub_name}")
    except ClientError as e:
        console.print(f"  [red]Erro DB Subnet Group:[/red] {e}")

    db_id = "assessment-lab-db"
    try:
        rds.create_db_instance(
            DBInstanceIdentifier=db_id,
            AllocatedStorage=20,
            DBInstanceClass="db.t3.micro",
            Engine="postgres",
            MasterUsername="assessmentadmin",
            MasterUserPassword="LabPassw0rd2026!",
            VpcSecurityGroupIds=[sg_db],
            DBSubnetGroupName=db_sub_name,
            PubliclyAccessible=False,
            StorageType="gp2",  # Proposital para recomendação de custo/performance (migrar para gp3)
            BackupRetentionPeriod=1,
            MultiAZ=False,      # Proposital para recomendação de Resiliência/Well-Architected
            StorageEncrypted=False, # Proposital para recomendação de Segurança
            Tags=[{"Key": "Name", "Value": db_id}, {"Key": "Environment", "Value": "Lab"}]
        )
        resources["rds_instance_id"] = db_id
        console.print(f"  [green]✓ RDS PostgreSQL disparado:[/green] {db_id} (20GB gp2, Single-AZ)")
    except ClientError as e:
        console.print(f"  [red]Erro ao criar RDS:[/red] {e}")

    # 7. Criar Hosted Zone no Route 53 (Privada na VPC)
    console.print("\n[yellow][Extra] Criando Hosted Zone Route 53 (lab.corp.internal)...[/yellow]")
    try:
        caller_ref = f"assessment-lab-{int(time.time())}"
        zone = r53.create_hosted_zone(
            Name="lab.corp.internal.",
            VPC={"VPCRegion": REGION, "VPCId": vpc_id},
            CallerReference=caller_ref,
            HostedZoneConfig={"Comment": "Zona DNS interna para simulacao de assessment", "PrivateZone": True}
        )
        zone_id = zone["HostedZone"]["Id"]
        resources["route53_zone_id"] = zone_id
        console.print(f"  [green]✓ Hosted Zone Route 53 criada:[/green] {zone_id} (lab.corp.internal)")

        # Adiciona registros de teste
        r53.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                "Changes": [
                    {
                        "Action": "CREATE",
                        "ResourceRecordSet": {
                            "Name": "api.lab.corp.internal.",
                            "Type": "A",
                            "TTL": 300,
                            "ResourceRecords": [{"Value": "10.50.1.50"}]
                        }
                    },
                    {
                        "Action": "CREATE",
                        "ResourceRecordSet": {
                            "Name": "db.lab.corp.internal.",
                            "Type": "CNAME",
                            "TTL": 300,
                            "ResourceRecords": [{"Value": "assessment-lab-db.internal"}]
                        }
                    }
                ]
            }
        )
        console.print("  [green]✓ Registros DNS A e CNAME criados para auditoria.[/green]")
    except ClientError as e:
        console.print(f"  [red]Erro ao criar Route 53:[/red] {e}")

    # Salva os recursos no JSON
    output_file = "E:\\01_Projetos\\Assessment_AWS\\lab\\lab_resources.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(resources, f, indent=2)

    console.print(f"\n[bold green]=== Deploy Concluído com Sucesso! ===[/bold green]")
    console.print(f"Arquivo de controle salvo em: [cyan]{output_file}[/cyan]")

if __name__ == "__main__":
    deploy()
