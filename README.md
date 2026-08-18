# 🔍 AD Software Audit — Auditoria de Software e Riscos em Active Directory

Projeto de portfólio em segurança da informação. Simula a coleta de inventário
de software instalado em máquinas de um domínio Active Directory e correlaciona
cada item com uma base demonstrativa de CVEs candidatas, gerando um relatório de priorização
por host e por unidade organizacional (OU).

<p align="center">
  <img src="./demo.gif" width="900">
</p>

> ⚠️ **Aviso:** os dados em `data/simulated_inventory.csv` são **fictícios**,
> criados apenas para fins de demonstração e estudo. Nenhuma empresa real está
> representada.

## Por que este projeto

Um dos primeiros passos de qualquer avaliação de segurança (seja um pentest,
uma auditoria interna ou um programa de vulnerability management) é responder:
**"o que exatamente está instalado no nosso ambiente, e o quão desatualizado
isso está?"**. Esse projeto automatiza essa resposta:

1. Coleta (aqui, simula) o inventário de software por host.
2. Correlaciona cada software/versão com referências candidatas para validação.
3. Calcula um score de risco por host, priorizando o que precisa de atenção primeiro.
4. Gera um relatório em Markdown e CSV, pronto para ser compartilhado.

## Arquitetura

```
ad-software-audit/
├── data/
│   ├── simulated_inventory.csv     # inventário fictício (hostname, OU, SO, software, versão)
│   └── known_vulnerabilities.json  # base local de CVEs conhecidas (fallback offline)
├── src/
│   └── risk_analysis.py            # script principal: coleta -> correlação -> relatório
├── reports/
│   ├── report.csv                  # saída em CSV (para importar em Excel/Power BI)
│   └── report.md                   # saída em Markdown (para leitura direta no GitHub)
├── tests/                         # testes de comparação, correlação e score
└── pyproject.toml                 # metadados e dependências opcionais
```

## Como rodar

```bash
python -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'

# Modo offline (usa a base local known_vulnerabilities.json) — não precisa de internet
.venv/bin/python src/risk_analysis.py --offline

# Modo online (consulta a API pública do NVD em tempo real)
.venv/bin/python -m pip install -e '.[online]'
.venv/bin/python src/risk_analysis.py --online
```

O relatório é gerado em `reports/report.md` e `reports/report.csv`.

Execute a validação automatizada com:

```bash
.venv/bin/python -m pytest
```

> A correlação por nome e versão é uma triagem educacional. Uma correspondência não confirma que o host seja vulnerável; produtos reais exigem CPE, intervalos de versão afetada e validação contextual.

## Metodologia de score de risco

Cada CVE encontrada soma pontos ao score do host, conforme a severidade:

| Severidade | Peso |
|---|---|
| Critical | 10 |
| High | 7 |
| Medium | 4 |
| Low | 1 |

O score por host é a soma de todas as vulnerabilidades encontradas nos
softwares instalados naquela máquina — quanto maior, mais prioritário.

## Adaptando para um Active Directory real

Este projeto usa dados simulados de propósito, para poder ser publicado
publicamente sem expor informações de uma empresa real. Para usar em um
ambiente real, a única peça que muda é a **coleta** — o restante do pipeline
(correlação de CVE + relatório) continua igual. Duas formas comuns de coletar
o inventário real de máquinas Windows em um domínio:

**1. PowerShell Remoting (a partir de um controlador de domínio ou jump host):**

```powershell
Get-ADComputer -Filter * | ForEach-Object {
    Invoke-Command -ComputerName $_.Name -ScriptBlock {
        Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
        Select-Object DisplayName, DisplayVersion, PSComputerName
    }
} | Export-Csv inventory.csv -NoTypeInformation
```

**2. A partir de Python, via WinRM** (bibliotecas como `pypsrp` ou `pywinrm`),
executando o mesmo tipo de consulta remotamente e normalizando a saída para o
mesmo formato de `simulated_inventory.csv` (hostname, ou, os, software, version).

Depois disso, basta apontar `INVENTORY_PATH` em `src/risk_analysis.py` para o
CSV real coletado — o restante do pipeline funciona sem alterações.

## Próximos passos (roadmap do portfólio)

- [ ] Adicionar suporte a CPE (Common Platform Enumeration) para correlação mais precisa com o NVD
- [ ] Exportar relatório também em HTML com gráficos (severidade por OU, evolução mês a mês)
- [x] Adicionar testes automatizados para comparação, correlação e score
- [ ] Publicar uma versão com coleta real via PowerShell Remoting contra um lab (GOAD)

## Disclaimer

Projeto educacional, construído para portfólio de estudos em segurança da
informação (trilha CompTIA PenTest+). Não deve ser usado para avaliar sistemas
sem autorização explícita do proprietário.

## Autor

Victor Magaldi — [LinkedIn](https://www.linkedin.com/in/victormmagaldi/) · [GitHub](https://github.com/victordmmdev)
