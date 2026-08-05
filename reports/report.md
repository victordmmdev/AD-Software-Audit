# Relatório de Risco — Inventário de Software do Active Directory

> ⚠️ Dados fictícios, gerados para fins de portfólio/estudo. Não representam uma empresa real.

## Resumo Executivo

- **Hosts analisados:** 13
- **Instalações de software analisadas:** 29
- **Vulnerabilidades identificadas:** 18
- **Distribuição por severidade:** Critical: 6 · High: 9 · Medium: 3

## Ranking de risco por host

| Host | Score de Risco | Critical | High | Medium | Low |
|---|---|---|---|---|---|
| WKS-FIN-001 | 24 | 1 | 2 | 0 | 0 |
| WKS-TI-001 | 24 | 2 | 0 | 1 | 0 |
| SRV-FILE-001 | 24 | 1 | 2 | 0 | 0 |
| WKS-VEN-001 | 24 | 1 | 2 | 0 | 0 |
| WKS-FIN-002 | 14 | 0 | 2 | 0 | 0 |
| SRV-WEB-001 | 14 | 1 | 0 | 1 | 0 |
| SRV-DB-001 | 7 | 0 | 1 | 0 | 0 |
| WKS-RH-002 | 4 | 0 | 0 | 1 | 0 |

## Detalhamento dos achados

| Host | OU | Software | Versão | CVE | Severidade | CVSS | Referência |
|---|---|---|---|---|---|---|---|
| WKS-FIN-001 | OU=Financeiro | Adobe Acrobat Reader DC | 21.007.20099 | CVE-2021-28550 | Critical | 9.8 | [CVE-2021-28550](https://nvd.nist.gov/vuln/detail/CVE-2021-28550) |
| WKS-TI-001 | OU=TI | WinRAR | 5.70 | CVE-2018-20250 | Critical | 7.8 | [CVE-2018-20250](https://nvd.nist.gov/vuln/detail/CVE-2018-20250) |
| WKS-TI-001 | OU=TI | Python | 3.9.0 | CVE-2021-3177 | Critical | 9.8 | [CVE-2021-3177](https://nvd.nist.gov/vuln/detail/CVE-2021-3177) |
| SRV-WEB-001 | OU=Servidores | Apache HTTP Server | 2.4.49 | CVE-2021-41773 | Critical | 9.8 | [CVE-2021-41773](https://nvd.nist.gov/vuln/detail/CVE-2021-41773) |
| SRV-FILE-001 | OU=Servidores | Adobe Acrobat Reader DC | 20.001.30020 | CVE-2021-28550 | Critical | 9.8 | [CVE-2021-28550](https://nvd.nist.gov/vuln/detail/CVE-2021-28550) |
| WKS-VEN-001 | OU=Vendas | Adobe Flash Player | 32.0.0.465 | CVE-2021-21017 | Critical | 9.8 | [CVE-2021-21017](https://nvd.nist.gov/vuln/detail/CVE-2021-21017) |
| WKS-FIN-001 | OU=Financeiro | Google Chrome | 110.0.5481.104 | CVE-2023-2033 | High | 8.8 | [CVE-2023-2033](https://nvd.nist.gov/vuln/detail/CVE-2023-2033) |
| WKS-FIN-001 | OU=Financeiro | 7-Zip | 19.00 | CVE-2022-29072 | High | 7.8 | [CVE-2022-29072](https://nvd.nist.gov/vuln/detail/CVE-2022-29072) |
| WKS-FIN-002 | OU=Financeiro | Mozilla Firefox | 102.0 | CVE-2022-38478 | High | 8.8 | [CVE-2022-38478](https://nvd.nist.gov/vuln/detail/CVE-2022-38478) |
| WKS-FIN-002 | OU=Financeiro | Java 8 Update 181 | 8.0.1810.13 | CVE-2018-2938 | High | 8.3 | [CVE-2018-2938](https://nvd.nist.gov/vuln/detail/CVE-2018-2938) |
| SRV-DB-001 | OU=Servidores | Microsoft SQL Server 2016 | 13.0.1601.5 | CVE-2020-0618 | High | 8.8 | [CVE-2020-0618](https://nvd.nist.gov/vuln/detail/CVE-2020-0618) |
| SRV-FILE-001 | OU=Servidores | 7-Zip | 16.02 | CVE-2022-29072 | High | 7.8 | [CVE-2022-29072](https://nvd.nist.gov/vuln/detail/CVE-2022-29072) |
| SRV-FILE-001 | OU=Servidores | Adobe Acrobat Reader DC | 20.001.30020 | CVE-2020-24432 | High | 7.8 | [CVE-2020-24432](https://nvd.nist.gov/vuln/detail/CVE-2020-24432) |
| WKS-VEN-001 | OU=Vendas | Google Chrome | 90.0.4430.212 | CVE-2023-2033 | High | 8.8 | [CVE-2023-2033](https://nvd.nist.gov/vuln/detail/CVE-2023-2033) |
| WKS-VEN-001 | OU=Vendas | Google Chrome | 90.0.4430.212 | CVE-2021-30551 | High | 8.8 | [CVE-2021-30551](https://nvd.nist.gov/vuln/detail/CVE-2021-30551) |
| WKS-RH-002 | OU=RH | VLC Media Player | 3.0.16 | CVE-2021-25801 | Medium | 6.5 | [CVE-2021-25801](https://nvd.nist.gov/vuln/detail/CVE-2021-25801) |
| WKS-TI-001 | OU=TI | PuTTY | 0.74 | CVE-2021-33500 | Medium | 5.9 | [CVE-2021-33500](https://nvd.nist.gov/vuln/detail/CVE-2021-33500) |
| SRV-WEB-001 | OU=Servidores | OpenSSL | 1.1.1k | CVE-2021-3712 | Medium | 6.1 | [CVE-2021-3712](https://nvd.nist.gov/vuln/detail/CVE-2021-3712) |

## Recomendações gerais

- Priorizar a atualização de software com achados **Critical** e **High**, começando pelos hosts com maior score de risco.
- Padronizar um processo de patch management com verificação periódica de versões instaladas.
- Avaliar a substituição de softwares descontinuados (ex.: Adobe Flash Player).
- Repetir esta análise periodicamente (ex.: mensal) e acompanhar a evolução do score de risco por host/OU.
