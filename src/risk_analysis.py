#!/usr/bin/env python3
"""
risk_analysis.py

Correlaciona um inventário de software (coletado de máquinas de um Active
Directory) com vulnerabilidades conhecidas (CVEs), gerando um relatório de
risco por host e por software.

Modo de uso:
    python src/risk_analysis.py --offline
    python src/risk_analysis.py --online   (consulta a API pública do NVD)

Este projeto usa dados FICTÍCIOS (data/simulated_inventory.csv) para fins de
portfólio. Para uso em um ambiente real, veja a seção "Adaptando para um AD
real" no README.md.
"""

import argparse
import csv
import json
import sys
import time
from collections import defaultdict
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
INVENTORY_PATH = BASE_DIR / "data" / "simulated_inventory.csv"
LOCAL_DB_PATH = BASE_DIR / "data" / "known_vulnerabilities.json"
REPORT_DIR = BASE_DIR / "reports"

SEVERITY_WEIGHT = {"Critical": 10, "High": 7, "Medium": 4, "Low": 1, "Unknown": 0}

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def load_inventory(path: Path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def load_local_db(path: Path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def version_leq(v1: str, v2: str) -> bool:
    """Compara versões no formato 'a.b.c.d' — retorna True se v1 <= v2."""
    def parts(v):
        return [int(x) for x in v.replace("-", ".").split(".") if x.isdigit()]
    p1, p2 = parts(v1), parts(v2)
    length = max(len(p1), len(p2))
    p1 += [0] * (length - len(p1))
    p2 += [0] * (length - len(p2))
    return p1 <= p2


def match_offline(software: str, version: str, local_db):
    matches = []
    for entry in local_db:
        if entry["software"].lower() == software.lower():
            if version_leq(version, entry["max_vulnerable_version"]):
                matches.append(entry)
    return matches


def query_nvd(software: str, version: str, session, delay=1.5):
    """Consulta a API pública do NVD por CVEs relacionadas ao software.
    Requer acesso à internet (não disponível neste ambiente de geração)."""
    import requests  # import local para não quebrar o modo offline sem a lib

    params = {"keywordSearch": f"{software} {version}", "resultsPerPage": 5}
    try:
        resp = session.get(NVD_API_URL, params=params, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        results = []
        for item in data.get("vulnerabilities", []):
            cve = item["cve"]
            cve_id = cve["id"]
            desc = next(
                (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
                "",
            )
            metrics = cve.get("metrics", {})
            severity, score = "Unknown", 0.0
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics:
                    m = metrics[key][0]
                    severity = m.get("cvssData", {}).get("baseSeverity", "Unknown")
                    score = m.get("cvssData", {}).get("baseScore", 0.0)
                    break
            results.append(
                {
                    "software": software,
                    "max_vulnerable_version": version,
                    "cve": cve_id,
                    "severity": severity.title() if severity else "Unknown",
                    "cvss": score,
                    "description": desc[:200],
                    "link": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                }
            )
        time.sleep(delay)  # respeita o rate limit público do NVD
        return results
    except Exception as exc:  # noqa: BLE001
        print(f"  [aviso] Falha ao consultar NVD para {software} {version}: {exc}", file=sys.stderr)
        return []


def analyze(inventory, local_db, online: bool):
    findings = []
    session = None
    if online:
        import requests

        session = requests.Session()

    for row in inventory:
        host, software, version = row["hostname"], row["software"], row["version"]
        matches = []
        if online:
            matches = query_nvd(software, version, session)
        if not matches:
            matches = match_offline(software, version, local_db)

        for m in matches:
            findings.append(
                {
                    "hostname": host,
                    "ou": row.get("ou", ""),
                    "os": row.get("os", ""),
                    "software": software,
                    "version": version,
                    "cve": m["cve"],
                    "severity": m["severity"],
                    "cvss": m["cvss"],
                    "description": m["description"],
                    "link": m["link"],
                }
            )
    return findings


def compute_host_risk(findings):
    host_scores = defaultdict(int)
    host_counts = defaultdict(lambda: defaultdict(int))
    for f in findings:
        host_scores[f["hostname"]] += SEVERITY_WEIGHT.get(f["severity"], 0)
        host_counts[f["hostname"]][f["severity"]] += 1
    return host_scores, host_counts


def write_csv_report(findings, path: Path):
    fields = ["hostname", "ou", "os", "software", "version", "cve", "severity", "cvss", "description", "link"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(findings)


def write_markdown_report(findings, host_scores, host_counts, path: Path, total_hosts: int, total_software: int):
    ranked_hosts = sorted(host_scores.items(), key=lambda x: x[1], reverse=True)
    sev_totals = defaultdict(int)
    for f in findings:
        sev_totals[f["severity"]] += 1

    lines = []
    lines.append("# Relatório de Risco — Inventário de Software do Active Directory")
    lines.append("")
    lines.append("> ⚠️ Dados fictícios, gerados para fins de portfólio/estudo. Não representam uma empresa real.")
    lines.append("")
    lines.append("## Resumo Executivo")
    lines.append("")
    lines.append(f"- **Hosts analisados:** {total_hosts}")
    lines.append(f"- **Instalações de software analisadas:** {total_software}")
    lines.append(f"- **Vulnerabilidades identificadas:** {len(findings)}")
    lines.append(
        f"- **Distribuição por severidade:** "
        + " · ".join(f"{k}: {v}" for k, v in sorted(sev_totals.items(), key=lambda x: -SEVERITY_WEIGHT.get(x[0], 0)))
    )
    lines.append("")
    lines.append("## Ranking de risco por host")
    lines.append("")
    lines.append("| Host | Score de Risco | Critical | High | Medium | Low |")
    lines.append("|---|---|---|---|---|---|")
    for host, score in ranked_hosts:
        c = host_counts[host]
        lines.append(
            f"| {host} | {score} | {c.get('Critical',0)} | {c.get('High',0)} | {c.get('Medium',0)} | {c.get('Low',0)} |"
        )
    lines.append("")
    lines.append("## Detalhamento dos achados")
    lines.append("")
    lines.append("| Host | OU | Software | Versão | CVE | Severidade | CVSS | Referência |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for f in sorted(findings, key=lambda x: -SEVERITY_WEIGHT.get(x["severity"], 0)):
        lines.append(
            f"| {f['hostname']} | {f['ou']} | {f['software']} | {f['version']} | {f['cve']} "
            f"| {f['severity']} | {f['cvss']} | [{f['cve']}]({f['link']}) |"
        )
    lines.append("")
    lines.append("## Recomendações gerais")
    lines.append("")
    lines.append("- Priorizar a atualização de software com achados **Critical** e **High**, começando pelos hosts com maior score de risco.")
    lines.append("- Padronizar um processo de patch management com verificação periódica de versões instaladas.")
    lines.append("- Avaliar a substituição de softwares descontinuados (ex.: Adobe Flash Player).")
    lines.append("- Repetir esta análise periodicamente (ex.: mensal) e acompanhar a evolução do score de risco por host/OU.")
    lines.append("")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def main():
    parser = argparse.ArgumentParser(description="Analisa risco de software em um inventário de AD.")
    parser.add_argument("--online", action="store_true", help="Consulta a API pública do NVD (requer internet).")
    parser.add_argument("--offline", action="store_true", help="Usa apenas a base local de vulnerabilidades (padrão).")
    args = parser.parse_args()

    online = args.online and not args.offline

    REPORT_DIR.mkdir(exist_ok=True)
    inventory = load_inventory(INVENTORY_PATH)
    local_db = load_local_db(LOCAL_DB_PATH)

    print(f"Analisando {len(inventory)} instalações de software em modo {'ONLINE (NVD)' if online else 'OFFLINE (base local)'}...")
    findings = analyze(inventory, local_db, online)

    host_scores, host_counts = compute_host_risk(findings)
    total_hosts = len({row["hostname"] for row in inventory})

    csv_path = REPORT_DIR / "report.csv"
    md_path = REPORT_DIR / "report.md"
    write_csv_report(findings, csv_path)
    write_markdown_report(findings, host_scores, host_counts, md_path, total_hosts, len(inventory))

    print(f"\n✔ {len(findings)} vulnerabilidades identificadas em {len(host_scores)} hosts.")
    print(f"✔ Relatório CSV: {csv_path}")
    print(f"✔ Relatório Markdown: {md_path}")


if __name__ == "__main__":
    main()
