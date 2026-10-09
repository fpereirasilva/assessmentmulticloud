"""
Gerador de Relatórios Oficiais SoftwareOne — Assessment AWS Multi-Conta
Layout: Landscape (Paisagem / 16:9 / A4 Paisagem)
Estilo: Fundo Branco Editorial Monocromático Premium (Black & White Editorial)
Branding Oficial: SoftwareOne ("Driven to Deliver", "All in One", Cloud-First & FinOps-optimized)
"""
import os
import json
import base64
from datetime import datetime
from rich.console import Console
from rich.table import Table

console = Console()

class ReportGenerator:
    def __init__(self, account_id: str, account_arn: str, findings: list, output_dir: str = "E:\\01_Projetos\\Assessment_AWS\\reports"):
        self.account_id = account_id
        self.account_arn = account_arn
        self.findings = findings
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def get_summary(self):
        summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        categories = {}
        for f in self.findings:
            sev = f.get("severity", "INFO").upper()
            cat = f.get("category", "Security")
            summary[sev] = summary.get(sev, 0) + 1
            categories[cat] = categories.get(cat, 0) + 1
        return summary, categories

    def print_terminal_summary(self):
        summary, categories = self.get_summary()
        table = Table(title="[bold]Resumo Executivo do Assessment AWS — SoftwareOne[/bold]")
        table.add_column("Severidade", style="bold")
        table.add_column("Total", justify="center")
        table.add_column("Impacto / Ação", style="dim")

        table.add_row("[red]CRITICAL[/red]", str(summary.get("CRITICAL", 0)), "Ação imediata recomendada (risco iminente de exposição)")
        table.add_row("[orange3]HIGH[/orange3]", str(summary.get("HIGH", 0)), "Vulnerabilidade grave ou falha de conformidade")
        table.add_row("[yellow]MEDIUM[/yellow]", str(summary.get("MEDIUM", 0)), "Risco moderado ou oportunidade de arquitetura / FinOps")
        table.add_row("[blue]LOW[/blue]", str(summary.get("LOW", 0)), "Melhoria de boas práticas / governança")
        table.add_row("[green]INFO[/green]", str(summary.get("INFO", 0)), "Configurações conformes ou informativas")
        console.print(table)

    def _get_logo_base64(self) -> str:
        logo_path = os.path.join(self.output_dir, "softwareone-logo.png")
        if os.path.exists(logo_path):
            try:
                with open(logo_path, "rb") as f:
                    b64 = base64.b64encode(f.read()).decode("utf-8")
                    return f"data:image/png;base64,{b64}"
            except Exception:
                pass
        return "https://images.seeklogo.com/logo-png/52/1/softwareone-logo-png_seeklogo-521617.png"

    def build_html_content(self) -> str:
        now_str = datetime.now().strftime("%d/%m/%Y às %H:%M")
        summary, categories = self.get_summary()
        total = len(self.findings)
        logo_src = self._get_logo_base64()

        # Cálculo de Score de Maturidade da Nuvem SoftwareOne (0 a 100)
        penalty = (summary.get("CRITICAL", 0) * 15) + (summary.get("HIGH", 0) * 5) + (summary.get("MEDIUM", 0) * 2)
        maturity_score = max(10, min(100, 100 - penalty))

        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        sorted_findings = sorted(self.findings, key=lambda x: order.index(x.get("severity", "INFO").upper()))

        # Linhas da tabela de findings
        table_rows = []
        for idx, f in enumerate(sorted_findings, 1):
            sev = f.get("severity", "INFO").upper()
            badge_class = f"badge-{sev.lower()}"
            table_rows.append(f"""
            <tr>
                <td class="text-center font-mono">#{idx:02d}</td>
                <td><span class="badge {badge_class}">{sev}</span></td>
                <td class="font-mono text-sm"><strong>{f.get('resource')}</strong><br><span class="text-muted">AWS {f.get('service')}</span></td>
                <td><span class="category-tag">{f.get('category', 'Security')}</span></td>
                <td>{f.get('issue')}</td>
                <td class="remediation-cell">{f.get('remediation')}</td>
            </tr>
            """)

        return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SoftwareOne — AWS Infrastructure Assessment &amp; Well-Architected</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;600;700&display=swap" rel="stylesheet">
<style>
    @page {{
        size: A4 landscape;
        margin: 10mm 14mm;
    }}
    * {{
        box-sizing: border-box;
        margin: 0;
        padding: 0;
    }}
    body {{
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
        background-color: #f7f7f8;
        color: #171717;
        line-height: 1.5;
        font-size: 13px;
        -webkit-print-color-adjust: exact;
        print-color-adjust: exact;
        padding: 24px;
    }}
    .page-wrapper {{
        max-width: 1560px;
        margin: 0 auto;
        background: #ffffff;
        border-radius: 8px;
        border: 1px solid #e5e5e5;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.04);
        padding: 36px 48px;
    }}

    /* Brand Top Strap */
    .brand-strap {{
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding-bottom: 12px;
        border-bottom: 1px solid #e5e5e5;
        margin-bottom: 24px;
        font-size: 11px;
        text-transform: uppercase;
        letter-spacing: 1.5px;
        color: #737373;
        font-weight: 600;
    }}
    .brand-strap .slogan {{
        color: #000000;
        font-weight: 700;
        letter-spacing: 2px;
    }}

    /* Header */
    .header {{
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding-bottom: 24px;
        border-bottom: 2px solid #000000;
        margin-bottom: 28px;
    }}
    .header-left {{
        display: flex;
        align-items: center;
        gap: 28px;
    }}
    .header-logo img {{
        height: 56px;
        width: auto;
        object-fit: contain;
        display: block;
    }}
    .header-title h1 {{
        font-size: 24px;
        font-weight: 800;
        letter-spacing: -0.5px;
        color: #000000;
        text-transform: uppercase;
        line-height: 1.2;
    }}
    .header-title p {{
        font-size: 13px;
        color: #525252;
        margin-top: 4px;
        font-weight: 500;
    }}
    .header-meta {{
        text-align: right;
        font-family: 'JetBrains Mono', monospace;
        font-size: 11px;
        color: #525252;
        line-height: 1.7;
    }}
    .header-meta strong {{
        color: #000000;
    }}

    /* Actions Bar */
    .actions-bar {{
        display: flex;
        justify-content: flex-end;
        gap: 12px;
        margin-bottom: 20px;
    }}
    .btn {{
        background: #ffffff;
        color: #000000;
        border: 1px solid #d4d4d4;
        padding: 9px 20px;
        font-size: 12px;
        font-weight: 600;
        border-radius: 6px;
        cursor: pointer;
        display: inline-flex;
        align-items: center;
        gap: 8px;
        transition: all 0.2s;
    }}
    .btn:hover {{
        background: #f5f5f5;
        border-color: #a3a3a3;
    }}
    .btn-primary {{
        background: #000000;
        color: #ffffff;
        border-color: #000000;
    }}
    .btn-primary:hover {{
        background: #262626;
    }}

    /* KPI Cards */
    .grid-kpis {{
        display: grid;
        grid-template-columns: 210px repeat(5, 1fr);
        gap: 14px;
        margin-bottom: 30px;
    }}
    .kpi-card {{
        background: #fafafa;
        border: 1px solid #e5e5e5;
        border-radius: 8px;
        padding: 16px 18px;
    }}
    .kpi-score {{
        background: #000000;
        border: 1px solid #000000;
        color: #ffffff;
        display: flex;
        flex-direction: column;
        justify-content: center;
        align-items: center;
        text-align: center;
    }}
    .kpi-score .score-val {{
        font-size: 44px;
        font-weight: 800;
        color: #ffffff;
        line-height: 1;
        font-family: 'JetBrains Mono', monospace;
    }}
    .kpi-score .score-label {{
        font-size: 11px;
        text-transform: uppercase;
        letter-spacing: 1.2px;
        color: #a3a3a3;
        margin-top: 8px;
        font-weight: 600;
    }}
    .kpi-title {{
        font-size: 11px;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        color: #737373;
        margin-bottom: 6px;
        font-weight: 700;
    }}
    .kpi-num {{
        font-size: 28px;
        font-weight: 800;
        color: #000000;
        font-family: 'JetBrains Mono', monospace;
    }}
    .kpi-sub {{
        font-size: 11px;
        color: #737373;
        margin-top: 4px;
    }}

    /* Badges B&W */
    .badge {{
        display: inline-block;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 10px;
        font-weight: 700;
        letter-spacing: 0.6px;
        text-transform: uppercase;
        font-family: 'JetBrains Mono', monospace;
        border: 1px solid transparent;
    }}
    .badge-critical {{
        background: #000000;
        color: #ffffff;
        border-color: #000000;
    }}
    .badge-high {{
        background: #333333;
        color: #ffffff;
    }}
    .badge-medium {{
        background: #666666;
        color: #ffffff;
    }}
    .badge-low {{
        background: #e5e5e5;
        color: #171717;
        border-color: #d4d4d4;
    }}
    .badge-info {{
        background: #f5f5f5;
        color: #737373;
        border-color: #e5e5e5;
    }}

    /* Section Titles */
    .section-title {{
        font-size: 16px;
        font-weight: 800;
        color: #000000;
        text-transform: uppercase;
        letter-spacing: 0.6px;
        padding-bottom: 10px;
        border-bottom: 1.5px solid #000000;
        margin: 36px 0 20px 0;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }}
    .section-title span {{
        font-size: 12px;
        color: #737373;
        font-weight: 500;
        text-transform: none;
        letter-spacing: normal;
    }}

    /* Strategic Vision / Roadmap Grid */
    .grid-3col {{
        display: grid;
        grid-template-columns: repeat(3, 1fr);
        gap: 18px;
        margin-bottom: 28px;
    }}
    .plan-card {{
        background: #ffffff;
        border: 1px solid #e5e5e5;
        border-radius: 8px;
        padding: 20px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.02);
    }}
    .plan-card h3 {{
        font-size: 13px;
        font-weight: 800;
        color: #000000;
        text-transform: uppercase;
        border-bottom: 1px solid #e5e5e5;
        padding-bottom: 10px;
        margin-bottom: 14px;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }}
    .plan-card h3 .horizon {{
        font-size: 11px;
        color: #525252;
        font-weight: 600;
        background: #f5f5f5;
        padding: 2px 8px;
        border-radius: 4px;
    }}
    .plan-list {{
        list-style: none;
    }}
    .plan-list li {{
        padding: 10px 0;
        border-bottom: 1px solid #f0f0f0;
        font-size: 12px;
        color: #404040;
        line-height: 1.45;
    }}
    .plan-list li:last-child {{
        border-bottom: none;
    }}
    .plan-list li strong {{
        color: #000000;
        display: block;
        margin-bottom: 3px;
        font-size: 12.5px;
    }}

    /* Table */
    .table-container {{
        overflow-x: auto;
        background: #ffffff;
        border: 1px solid #e5e5e5;
        border-radius: 8px;
    }}
    table {{
        width: 100%;
        border-collapse: collapse;
        text-align: left;
    }}
    th {{
        background: #fafafa;
        color: #525252;
        font-size: 10.5px;
        text-transform: uppercase;
        letter-spacing: 0.6px;
        padding: 13px 16px;
        border-bottom: 1.5px solid #000000;
        font-weight: 700;
    }}
    td {{
        padding: 12px 16px;
        border-bottom: 1px solid #f0f0f0;
        vertical-align: top;
        font-size: 12.5px;
        color: #262626;
    }}
    tr:hover td {{
        background: #fdfdfd;
    }}
    .category-tag {{
        display: inline-block;
        background: #f5f5f5;
        color: #262626;
        border: 1px solid #e5e5e5;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 10.5px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.3px;
    }}
    .remediation-cell {{
        font-family: 'JetBrains Mono', monospace;
        font-size: 11px;
        color: #000000;
        background: #f9f9fa;
        padding: 8px 12px;
        border-radius: 4px;
        border-left: 3px solid #000000;
        line-height: 1.4;
    }}
    .text-center {{ text-align: center; }}
    .font-mono {{ font-family: 'JetBrains Mono', monospace; }}
    .text-sm {{ font-size: 11.5px; }}
    .text-muted {{ color: #737373; }}

    /* Footer */
    .footer {{
        margin-top: 40px;
        padding-top: 20px;
        border-top: 1.5px solid #000000;
        display: flex;
        justify-content: space-between;
        align-items: center;
        font-size: 11.5px;
        color: #525252;
    }}
    .footer strong {{
        color: #000000;
    }}

    /* PRINT MEDIA (A4 LANDSCAPE) */
    @media print {{
        body {{
            background: #ffffff !important;
            padding: 0 !important;
            color: #000000 !important;
        }}
        .page-wrapper {{
            max-width: 100% !important;
            box-shadow: none !important;
            border: none !important;
            padding: 0 !important;
        }}
        .actions-bar {{
            display: none !important;
        }}
        tr {{
            page-break-inside: avoid !important;
        }}
        .plan-card {{
            page-break-inside: avoid !important;
        }}
    }}
</style>
</head>
<body>
<div class="page-wrapper">

    <!-- Brand Strap -->
    <div class="brand-strap">
        <span>SOFTWAREONE CLOUD SERVICES &amp; ADVISORY</span>
        <span class="slogan">ALL IN ONE — DRIVEN TO DELIVER</span>
    </div>

    <!-- Actions Bar (Apenas Web) -->
    <div class="actions-bar">
        <button class="btn btn-primary" onclick="window.print()">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 9V2h12v7M6 18H4a2 2 0 01-2-2v-5a2 2 0 012-2h16a2 2 0 012 2v5a2 2 0 01-2 2h-2"/><path d="M6 14h12v8H6z"/></svg>
            Exportar PDF / Imprimir em Paisagem (A4)
        </button>
    </div>

    <!-- Header Oficial SoftwareOne -->
    <div class="header">
        <div class="header-left">
            <div class="header-logo">
                <img src="{logo_src}" alt="SoftwareOne Logo">
            </div>
            <div class="header-title">
                <h1>AWS Infrastructure Assessment &amp; Well-Architected</h1>
                <p>Relatório Executivo &amp; Técnico de Maturidade de Nuvem | Otimizado por FinOps &amp; Segurança</p>
            </div>
        </div>
        <div class="header-meta">
            <div>ACCOUNT ID: <strong>{self.account_id}</strong></div>
            <div>DATA DE EMISSÃO: <strong>{now_str}</strong></div>
            <div>IDENTIDADE AUDITORA: <strong>{self.account_arn.split('/')[-1]}</strong></div>
            <div>BENCHMARKS: <strong>CIS AWS Foundations v3.0 | Well-Architected</strong></div>
        </div>
    </div>

    <!-- KPI Cards & Maturity Index -->
    <div class="grid-kpis">
        <div class="kpi-card kpi-score">
            <div class="score-val">{maturity_score}</div>
            <div class="score-label">Índice de Maturidade</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-title">Total Apontamentos</div>
            <div class="kpi-num">{total}</div>
            <div class="kpi-sub">Itens avaliados na infraestrutura</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-title">🔴 Crítico</div>
            <div class="kpi-num">{summary.get('CRITICAL', 0)}</div>
            <div class="kpi-sub">Risco imediato de exposição</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-title">🟠 Alto</div>
            <div class="kpi-num">{summary.get('HIGH', 0)}</div>
            <div class="kpi-sub">Vulnerabilidade estrutural</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-title">🟡 Médio (FinOps/HA)</div>
            <div class="kpi-num">{summary.get('MEDIUM', 0)}</div>
            <div class="kpi-sub">Oportunidades de custo &amp; DR</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-title">🔵 Baixo / Governança</div>
            <div class="kpi-num">{summary.get('LOW', 0)}</div>
            <div class="kpi-sub">Padronização de tags &amp; políticas</div>
        </div>
    </div>

    <!-- Visão Estratégica SoftwareOne: Roadmap de Modernização -->
    <div class="section-title">
        Visão Estratégica SoftwareOne: Roadmap de Modernização de Infraestrutura
        <span>Planejamento orientado a FinOps, Segurança e Resiliência Operacional</span>
    </div>

    <div class="grid-3col">
        <div class="plan-card">
            <h3>Fase 1: Quick-Wins &amp; Estancamento de Risco <span class="horizon">0 a 15 Dias</span></h3>
            <ul class="plan-list">
                <li><strong>MFA Obrigatório no Root &amp; Console IAM</strong>Blindagem imediata das credenciais mestras e imposição de MFA via política para todos os usuários com acesso console.</li>
                <li><strong>Fechamento do Perímetro Externo (SG 0.0.0.0/0)</strong>Remover exposição pública direta das portas 22 (SSH) e 3389 (RDP). Adotar AWS Systems Manager (SSM) Session Manager ou Bastion privado.</li>
                <li><strong>S3 Block Public Access Global</strong>Ativar as 4 travas do S3 Block Public Access a nível de conta, impedindo qualquer vazamento acidental de buckets ou objetos.</li>
            </ul>
        </div>
        <div class="plan-card">
            <h3>Fase 2: FinOps, Hardening &amp; Performance <span class="horizon">15 a 45 Dias</span></h3>
            <ul class="plan-list">
                <li><strong>Otimização de Custos: Migração EBS gp2 para gp3</strong>Migrar volumes de armazenamento de gp2 para gp3 sem downtime: redução instantânea de até 20% no custo por GB e ganho de baseline de 3.000 IOPS.</li>
                <li><strong>Mitigação de SSRF via IMDSv2</strong>Forçar HttpTokens=required em 100% das instâncias EC2, bloqueando ataques de Server-Side Request Forgery que visam roubo de IAM Roles.</li>
                <li><strong>Criptografia Padrão em Repouso (KMS)</strong>Habilitar KMS padrão para EBS e RDS para conformidade com LGPD, ISO 27001 e SOC 2.</li>
            </ul>
        </div>
        <div class="plan-card">
            <h3>Fase 3: Resiliência, DR &amp; Governança <span class="horizon">45 a 90 Dias</span></h3>
            <ul class="plan-list">
                <li><strong>Alta Disponibilidade (Multi-AZ) &amp; PITR no RDS</strong>Habilitar Multi-AZ em bancos críticos com failover síncrono e estender janela de backup para 14 a 30 dias para suporte a PITR.</li>
                <li><strong>Rastreabilidade de Rede: VPC Flow Logs</strong>Ativar VPC Flow Logs em todas as subnets com agregação no CloudWatch Logs ou S3 para investigações de segurança e tráfego anômalo.</li>
                <li><strong>AWS Tag Policies &amp; FinOps Allocation</strong>Implantar governança automatizada de tags (Environment, Project, CostCenter) via AWS Organizations para alocação precisa de custos.</li>
            </ul>
        </div>
    </div>

    <!-- Tabela Detalhada dos Apontamentos Técnicos -->
    <div class="section-title">
        Inventário Detalhado de Apontamentos &amp; Recomendações Técnicas
        <span>Classificado rigorosamente por criticidade decrescente</span>
    </div>

    <div class="table-container">
        <table>
            <thead>
                <tr>
                    <th style="width: 45px;" class="text-center">#</th>
                    <th style="width: 95px;">Severidade</th>
                    <th style="width: 250px;">Recurso / Serviço</th>
                    <th style="width: 145px;">Pilar Well-Architected</th>
                    <th>Diagnóstico Técnico &amp; Impacto</th>
                    <th style="width: 400px;">Plano de Ação / Remediação Técnica</th>
                </tr>
            </thead>
            <tbody>
                {''.join(table_rows)}
            </tbody>
        </table>
    </div>

    <!-- Footer Oficial SoftwareOne -->
    <div class="footer">
        <div>
            <strong>SoftwareOne Brasil</strong> — Av. Andrômeda, 885, 16° andar, Barueri - SP | <strong>Driven to Deliver</strong><br>
            Metodologia baseada em AWS Well-Architected Framework e CIS Benchmark | All in One
        </div>
        <div style="text-align: right;">
            Documento Confidencial © SoftwareOne AG 2026<br>
            Todos os direitos reservados
        </div>
    </div>

</div>
</body>
</html>
"""

    def generate_html_landscape(self) -> str:
        timestamp_file = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.join(self.output_dir, f"softwareone_aws_assessment_landscape_{self.account_id}_{timestamp_file}.html")
        content = self.build_html_content()
        with open(filename, "w", encoding="utf-8") as f:
            f.write(content)
        return filename

    def generate_markdown(self) -> str:
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        timestamp_file = datetime.now().strftime("%Y%m%d_%H%M%S")
        summary, categories = self.get_summary()

        filename = f"{self.output_dir}\\assessment_report_{self.account_id}_{timestamp_file}.md"

        md = []
        md.append(f"# SoftwareOne — Relatório de Assessment de Infraestrutura AWS\n")
        md.append(f"**All in One — Driven to Deliver**  ")
        md.append(f"**Data de Emissão:** {now_str} | **Account ID:** `{self.account_id}` | **Identidade:** `{self.account_arn}`\n")
        md.append("---\n")
        md.append("## 1. Sumário Executivo de Maturidade\n")
        md.append("| Nível de Severidade | Quantidade | Risco / Prioridade |")
        md.append("| :--- | :---: | :--- |")
        md.append(f"| **🔴 CRITICAL** | {summary.get('CRITICAL', 0)} | Risco imediato de invasão ou indisponibilidade |")
        md.append(f"| **🟠 HIGH** | {summary.get('HIGH', 0)} | Falha grave de segurança ou desvio de conformidade |")
        md.append(f"| **🟡 MEDIUM** | {summary.get('MEDIUM', 0)} | Oportunidade de FinOps (custo) ou Resiliência (DR) |")
        md.append(f"| **🔵 LOW** | {summary.get('LOW', 0)} | Governança e padronização de tags |")
        md.append(f"| **🟢 INFO** | {summary.get('INFO', 0)} | Conforme / Informativo |\n")

        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        sorted_findings = sorted(self.findings, key=lambda x: order.index(x.get("severity", "INFO").upper()))
        md.append("## 2. Detalhamento dos Apontamentos Técnicos\n")
        for idx, f in enumerate(sorted_findings, 1):
            md.append(f"### #{idx:02d} [{f.get('severity')}] {f.get('resource')} ({f.get('service')})")
            md.append(f"- **Pilar Well-Architected:** {f.get('category', 'Security')}")
            md.append(f"- **Diagnóstico:** {f.get('issue')}")
            md.append(f"- **Remediação Recomendada:** {f.get('remediation')}\n")

        md.append("---\n")
        md.append("**SoftwareOne Brasil** | Av. Andrômeda, 885, Barueri - SP | © SoftwareOne AG 2026\n")

        with open(filename, "w", encoding="utf-8") as out:
            out.write("\n".join(md))
        return filename

    def generate_json(self) -> str:
        timestamp_file = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.output_dir}\\assessment_report_{self.account_id}_{timestamp_file}.json"
        summary, categories = self.get_summary()

        payload = {
            "organization": "SoftwareOne",
            "brand_promise": "Driven to Deliver",
            "account_id": self.account_id,
            "account_arn": self.account_arn,
            "timestamp": datetime.now().isoformat(),
            "summary": summary,
            "categories": categories,
            "total_findings": len(self.findings),
            "findings": self.findings
        }
        with open(filename, "w", encoding="utf-8") as out:
            json.dump(payload, out, indent=2, ensure_ascii=False)
        return filename
