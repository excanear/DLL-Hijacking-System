# Política de Segurança

## Reportando Vulnerabilidades

⚠️ **NÃO abra issues públicas para vulnerabilidades.**

Se você descobrir uma vulnerabilidade, por favor reporte de forma responsável:

1. **Email:** security@seu-dominio.com com assunto `[SECURITY] DLL Hijacking Defense`
2. **Inclua:**
   - Descrição clara da vulnerabilidade
   - Passos detalhados para reproduzir
   - Impacto potencial
   - Qualquer PoC (Proof of Concept) — em privado

3. **Prazo:** Aguarde confirmação dentro de 48 horas

## Processo de Divulgação Responsável

1. **Relatório** → Você reporta vulnerabilidade privadamente
2. **Investigação** → Confirmamos em até 1 semana
3. **Correção** → Desenvolvemos patch em sigilo
4. **Lançamento** → Publicamos patch em release security
5. **Divulgação** → Publicamos CVE após 30 dias do patch

## Tipos de Vulnerabilidades Críticas

Consideramos críticas:
- Buffer overflows / UAF
- Data races / condições de corrida
- Bypass de validação
- Escalação de privilégio
- Execução remota de código (RCE)

## Suporte de Segurança

| Versão | Status | Até |
|--------|--------|-----|
| 1.0+ | Suportada | TBD |
| < 1.0 | Suportada | TBD |

## Boas Práticas de Segurança para Usuários

1. **Manter atualizado** — Aplique patches quando lançados
2. **Base de dados de hashes** — Popule `hash_database.json` com seus apps confiáveis
3. **ACLs** — Sempre execute `Set-Acls.ps1` antes de deploy
4. **Logs** — Monitore arquivos de segurança em `logs/`
5. **Política** — Ajuste thresholds em `policy/defaults.json` para seu risco

## Perguntas?

📧 security@seu-dominio.com
