import pathlib

content = """\
<div align="center">

<img src="https://img.shields.io/badge/plataforma-Windows%2010%2B-0078D4?style=for-the-badge&logo=windows&logoColor=white"/>
<img src="https://img.shields.io/badge/C%2B%2B-17-00599C?style=for-the-badge&logo=cplusplus&logoColor=white"/>
<img src="https://img.shields.io/badge/.NET-8.0-512BD4?style=for-the-badge&logo=dotnet&logoColor=white"/>
<img src="https://img.shields.io/badge/build-MSBuild%2017-blueviolet?style=for-the-badge&logo=visualstudio&logoColor=white"/>
<img src="https://img.shields.io/badge/testes-GoogleTest-orange?style=for-the-badge"/>
<img src="https://img.shields.io/badge/licença-MIT-yellow?style=for-the-badge"/>

# DLL Hijacking Defense System

**Proteção de produção, em profundidade, contra DLL hijacking para aplicações Windows 10+.**

Cinco camadas de segurança interligadas — endurecimento da ordem de busca, validação pré-carregamento, pontuação de risco composta, monitoramento em tempo real e auditoria offline — coordenadas por uma única fachada C++17, expostas via bridge C++/CLI e operadas por uma GUI WPF completa de gerenciamento.

[Arquitetura](#arquitetura) · [Início Rápido](#início-rápido) · [Referência da API](#referência-da-api) · [Configuração](#referência-de-configuração) · [GUI](#gui) · [Modelo de Ameaças](#modelo-de-ameaças)

</div>

---

## Sumário

1. [Visão Geral](#visão-geral)
2. [Arquitetura](#arquitetura)
3. [Pré-requisitos](#pré-requisitos)
4. [Início Rápido](#início-rápido)
5. [Configuração Inicial](#configuração-inicial)
6. [Implantação](#implantação)
7. [Referência da API](#referência-da-api)
8. [Referência de Configuração](#referência-de-configuração)
9. [Monitoramento em Tempo Real](#monitoramento-em-tempo-real)
10. [Formato de Log](#formato-de-log)
11. [GUI](#gui)
12. [Modelo de Ameaças](#modelo-de-ameaças)
13. [Referência de Build](#referência-de-build)

---

## Visão Geral

O DLL Hijacking Defense System (DHD) é uma **biblioteca estática C++17** para Windows 10+ que protege processos hospedeiros contra DLL hijacking combinando cinco camadas de defesa independentes e coordenadas:

| # | Camada | Módulo | O que faz |
|---|---|---|---|
| 1 | **Endurecimento da ordem de busca** | `SecureLoader` | Remove CWD e PATH da ordem implícita de busca de DLLs via `SetDefaultDllDirectories` na inicialização do processo |
| 2 | **Validação pré-carregamento** | `DLLValidator` | Pipeline de 4 estágios: whitelist de caminho → heurísticas de nome → verificação SHA-256 → assinatura Authenticode |
| 3 | **Pontuação de risco contextual** | `RiskAnalyzer` | Aplica 7 regras de detecção (R001–R007) e produz pontuação composta `[0,0, 1,0]`; decide `Permitir / Alertar / Bloquear` |
| 4 | **Monitoramento em tempo real** | `RuntimeMonitor` | Eventos ETW `ImageLoad` + polling via `EnumProcessModules` para detectar DLLs injetadas após inicialização |
| 5 | **Auditoria offline** | `AuditScanner` | Scanner PE independente — identifica DLLs fantasma, diretórios graváveis na ordem de busca e fraquezas de ACL antes da implantação |

Todas as cinco camadas são inicializadas e encerradas por uma única fachada: `InitializeDefenseSystem` / `ShutdownDefenseSystem`.

Um **bridge C++/CLI** (`DhdBridge.dll`) expõe a API completa para qualquer consumidor gerenciado (.NET 8), e uma **GUI WPF de gerenciamento** (`DhdGui.exe`) fornece dashboards em tempo real, validação de DLL, scan de auditoria, navegador de logs e configuração do sistema — tudo alimentado pelo mesmo motor nativo.

---

## Arquitetura

```
┌─────────────────────────────────────────────────────────────┐
│                    Aplicação Hospedeira                     │
│         InitializeDefenseSystem(&cfg)  ─────── uma chamada  │
└─────────────────────┬───────────────────────────────────────┘
                      │
           ┌──────────▼──────────┐
           │    DefenseSystem    │  core/defense_system.h
           │   (fachada ordenada)│
           └──┬──┬──┬──┬──┬──┬──┘
              │  │  │  │  │  │
    ┌─────────▼┐ │  │  │  │  └──────────────────────┐
    │ Logging  │ │  │  │  │     ┌───────────────────▼─┐
    │ Engine   │ │  │  │  │     │  Runtime Monitor    │
    │ Async    │ │  │  │  │     │  ETW ImageLoad +    │
    │ JSON/HMAC│ │  │  │  │     │  Polling de Módulos │
    └──────────┘ │  │  │  │     └─────────────────────┘
          ┌──────▼┐ │  │  │
          │Policy │ │  │  └──────────────────────┐
          │Manager│ │  │     ┌───────────────────▼─┐
          │JSON   │ │  │     │   Risk Analyzer     │
          │regras │ │  │     │   Regras R001–R007  │
          └───────┘ │  │     │   Detecção de burst │
             ┌──────▼┐ │     └─────────────────────┘
             │  DLL  │ │
             │Valida-│ │
             │ tor   │ │
             │4 est. │ │
             └───────┘ │
                ┌──────▼──────┐
                │Secure Loader│
                │SetDefault-  │
                │DllDirectories
                └─────────────┘
```

### Estrutura do Repositório

```
dll-hijack-defense/
├── core/               # SecureLoader, DLLValidator, DefenseSystem, Hardening
├── intelligence/       # RiskAnalyzer, LoggingEngine
├── monitor/            # RuntimeMonitor (ETW + polling)
├── audit/              # AuditScanner + ferramenta CLI
├── shared/             # Tipos, constantes, PolicyManager
├── tools/              # bootstrap_hashdb — popula hash_database.json
├── tests/              # 5 executáveis GoogleTest
├── scripts/            # Set-Acls.ps1, Update-HashDatabase.ps1
├── policy/
│   └── defaults.json   # Configuração padrão de política
├── config/
│   └── hash_database.json  # Banco de hashes de DLL (populado pelo bootstrap)
├── DhdBridge/          # Bridge C++/CLI .NET 8 → DhdBridge.dll
└── DhdGui/             # GUI WPF .NET 8 → DhdGui.exe
```

### Mapa de Módulos

| Diretório | Saída | Responsabilidade |
|---|---|---|
| `shared/` | `shared.lib` | Tipos, constantes, `PolicyManager` |
| `core/` | `core.lib` | `SecureLoader`, `DLLValidator`, `DefenseSystem`, `Hardening` |
| `intelligence/` | `intelligence.lib` | `RiskAnalyzer`, `LoggingEngine` |
| `monitor/` | `monitor.lib` | `RuntimeMonitor` |
| `audit/` | `audit.lib` + `audit_scanner_cli.exe` | Scanner de auditoria PE offline |
| `tools/` | `bootstrap_hashdb.exe` | Bootstrapper do banco de hashes |
| `tests/` | 5 × `test_*.exe` | Testes unitários (GoogleTest) |
| `DhdBridge/` | `DhdBridge.dll` | Wrapper gerenciado C++/CLI |
| `DhdGui/` | `DhdGui.exe` | GUI de gerenciamento WPF |

---

## Pré-requisitos

| Requisito | Versão mínima | Observações |
|---|---|---|
| Windows | 10 (build 19041) | Alvo `_WIN32_WINNT=0x0A00` |
| Visual Studio Build Tools | 2022 (MSVC 14.3x) | Carga VC++ + suporte C++/CLI + Windows 11 SDK |
| CMake | 3.20 | Backend C++ nativo |
| .NET SDK | 8.0 | DhdBridge e DhdGui |
| PowerShell | 5.1+ | Scripts operacionais |
| Internet (tempo de configuração) | — | GoogleTest via `FetchContent` |

> **Instalar Build Tools automaticamente (execute como Administrador):**
> ```powershell
> winget install Microsoft.VisualStudio.2022.BuildTools `
>   --override "--quiet --wait --add Microsoft.VisualStudio.Workload.VCTools `
>               --add Microsoft.VisualStudio.Component.VC.CLI.Support `
>               --add Microsoft.VisualStudio.Component.Windows11SDK.22621 `
>               --includeRecommended"
> ```

---

## Início Rápido

```powershell
# 1. Configurar e compilar o backend nativo
cmake -B C:\\build\\dhd -S . -G "Visual Studio 17 2022" -A x64
cmake --build C:\\build\\dhd --config Release --parallel

# 2. Popular o banco de hashes (obrigatório antes da primeira execução)
C:\\build\\dhd\\tools\\Release\\bootstrap_hashdb.exe

# 3. Compilar o bridge C++/CLI
msbuild DhdBridge\\DhdBridge.vcxproj /p:Configuration=Release /p:Platform=x64

# 4. Compilar a GUI WPF
dotnet build DhdGui\\DhdGui.csproj -c Release -r win-x64

# 5. Executar a GUI
DhdGui\\bin\\Release\\net8.0-windows\\win-x64\\DhdGui.exe
```

> Para integração somente de biblioteca (sem GUI), pule os passos 3–5 e vincule às libs estáticas.

---

## Configuração Inicial

O banco de hashes deve ser populado antes que o motor de validação possa realizar pontuação baseada em hash. Até lá, o motor aplica a penalidade `+0,10` de hash desconhecido a cada DLL.

### Opção A — Bootstrapper C++ (recomendado para CI/CD)

```powershell
.\\build\\tools\\Release\\bootstrap_hashdb.exe
```

| Código de saída | Significado |
|---|---|
| `0` | Todos os hashes de DLL calculados e gravados |
| `1` | Uma ou mais DLLs não encontradas (parcial — verifique a saída) |
| `2` | Erro fatal (E/S de arquivo ou falha BCrypt) |

### Opção B — Script PowerShell

```powershell
# Requer privilégios de Administrador
.\\scripts\\Update-HashDatabase.ps1

# Forçar substituição de hashes existentes
.\\scripts\\Update-HashDatabase.ps1 -Force
```

Ambas as ferramentas calculam SHA-256 via BCrypt do Windows, resolvem cada DLL via `trusted_path` → System32 → SysWOW64 e gravam `db_integrity_hash` — um SHA-256 sobre o JSON canônico — que `VerifyHashDatabaseIntegrity` valida na inicialização.

---

## Implantação

### Passo 1 — Compilar para Release

```powershell
cmake --build C:\\build\\dhd --config Release --parallel
```

### Passo 2 — Popular o banco de hashes

```powershell
.\\build\\tools\\Release\\bootstrap_hashdb.exe
```

### Passo 3 — Endurecer ACLs (execute como Administrador)

```powershell
.\\scripts\\Set-Acls.ps1 -InstallRoot "C:\\Program Files\\MinhaApp\\dhd"

# Visualizar sem aplicar
.\\scripts\\Set-Acls.ps1 -WhatIf
```

| Caminho | Permissões aplicadas |
|---|---|
| Diretório de logs | `SYSTEM` + `Administrators` controle total; sem outros principals |
| Arquivo de política | `SYSTEM` + `Administrators` total; `Everyone` somente leitura |
| Banco de hashes | Mesmo que o arquivo de política |

### Passo 4 — Auditoria pré-implantação

```powershell
# Escanear um único executável
.\\build\\audit\\Release\\audit_scanner_cli.exe `
    --exe "C:\\MinhaApp\\minhaapp.exe" --report "C:\\Relatorios\\audit.json"

# Escanear um diretório (profundidade limitada)
.\\build\\audit\\Release\\audit_scanner_cli.exe `
    --dir "C:\\MinhaApp" --depth 2 --report "C:\\Relatorios\\audit.json"
```

| Código de saída | Significado |
|---|---|
| `0` | Nenhuma ocorrência |
| `1` | Uma ou mais ocorrências — revise o relatório JSON |
| `2` | Erro fatal |

### Passo 5 — Vincular e inicializar

Vincule contra as cinco libs estáticas e chame `InitializeDefenseSystem` no início de `main`.

---

## Referência da API

### Incluindo o cabeçalho

```cpp
#include "defense_system.h"   // Único cabeçalho público necessário
// Todos os símbolos em namespace dhd
```

---

### `DefenseSystemConfig`

```cpp
struct DefenseSystemConfig {
    wchar_t policy_file_path[MAX_PATH];  // Padrão: "policy\\defaults.json"
    wchar_t hash_db_path[MAX_PATH];      // Padrão: "config\\hash_database.json"
    wchar_t log_directory[MAX_PATH];     // Padrão: "logs"
    DWORD   monitor_poll_interval_ms;    // 0 → 5.000 ms
    MonitorCallback monitor_callback;    // Opcional — chamado a cada ocorrência em tempo real
    void*   monitor_user_data;           // Passado literalmente ao callback
};
```

Todos os campos de caminho são resolvidos relativos ao diretório de trabalho do processo quando vazios (inicializados com zero).

---

### `InitializeDefenseSystem`

```cpp
BOOL InitializeDefenseSystem(const DefenseSystemConfig* config);
```

Inicialização ordenada em 6 passos:

| Passo | Componente | Em caso de falha |
|---|---|---|
| 1 | `LoggingEngine` — inicia gravador de log assíncrono | Não fatal — Warning registrado |
| 2 | `PolicyManager` — carrega e valida JSON de política | Não fatal — Warning registrado |
| 3 | `DLLValidator` — carrega banco de hashes, verifica integridade | Não fatal — pontuação degradada |
| 4 | `RiskAnalyzer` — inicializa buffer de burst | Não fatal |
| 5 | `SecureLoader` — chama `SetDefaultDllDirectories` | **Fatal** se a API não estiver disponível |
| 6 | `RuntimeMonitor` — inicia sessão ETW + thread de polling | Não fatal — recorre ao polling |

Retorna `FALSE` apenas se já inicializado (idempotente — segunda chamada é no-op).

```cpp
#include "defense_system.h"

int WINAPI wWinMain(HINSTANCE, HINSTANCE, LPWSTR, int)
{
    dhd::DefenseSystemConfig cfg{};  // zero-inicializar -> todos os padrões

    wcscpy_s(cfg.policy_file_path, L"C:\\\\MinhaApp\\\\config\\\\policy.json");
    wcscpy_s(cfg.hash_db_path,     L"C:\\\\MinhaApp\\\\config\\\\hash_database.json");
    wcscpy_s(cfg.log_directory,    L"C:\\\\ProgramData\\\\MinhaApp\\\\logs");
    cfg.monitor_poll_interval_ms = 3000;

    cfg.monitor_callback = [](const dhd::AuditFinding* f, void*) {
        if (f->severity >= dhd::LogSeverity::Alert)
            AcionarRespostaAIncidente(*f);
    };

    dhd::InitializeDefenseSystem(&cfg);

    // ... lógica da aplicação ...

    dhd::ShutdownDefenseSystem();
    return 0;
}
```

---

### `ShutdownDefenseSystem`

```cpp
void ShutdownDefenseSystem();
```

Encerramento ordenado: para `RuntimeMonitor` → drena `LoggingEngine` → descarrega e zera a chave HMAC.  
Seguro para chamar de qualquer thread. No-op se não inicializado.

---

### `IsDefenseSystemInitialized`

```cpp
BOOL IsDefenseSystemInitialized();
```

Retorna `TRUE` se o sistema estiver ativo.

---

### `SecureLoadLibrary` (avançado)

Carrega uma DLL específica pelo pipeline de validação completo:

```cpp
#include "secure_loader.h"

dhd::LoadRequest req{};
wcscpy_s(req.dll_path, L"C:\\\\Windows\\\\System32\\\\version.dll");

dhd::LoadResult result = dhd::SecureLoadLibrary(req);
if (result.action == dhd::LoadAction::Allowed) {
    // result.module_handle — HMODULE válido
} else {
    // result.block_reasons — bitfield de flags BR_*
    // result.risk_score    — [0,0, 1,0]
}
```

---

### AuditScanner (programático)

```cpp
#include "audit_scanner.h"

dhd::ScanOptions opts{};
opts.check_phantom_dlls       = true;
opts.check_writable_dirs      = true;
opts.check_acl_permissiveness = true;
opts.max_recursion_depth      = 3;
wcscpy_s(opts.target_directory, L"C:\\\\MinhaApp");

dhd::ScanResult result = dhd::RunAuditScan(opts);
// result.findings            — vector<AuditFinding>
// result.executables_scanned
// result.phantom_count
// result.writable_dir_count
// result.acl_issue_count
```

---

## Referência de Configuração

### `policy/defaults.json`

```jsonc
{
  "version": 1,
  "mode": "AUDIT",
  "detection_rules": [
    { "id": "R001", "enabled": true, "description": "DLL fora de System32/SysWOW64/WinSxS" },
    { "id": "R002", "enabled": true, "description": "Assinatura Authenticode ausente ou inválida" },
    { "id": "R003", "enabled": true, "description": "DLL carregada de caminho temporário/gravável por usuário" },
    { "id": "R004", "enabled": true, "description": "Distância Levenshtein do nome ≤ 2 de DLL do sistema" },
    { "id": "R005", "enabled": true, "description": "Substituição de homoglifo Unicode no nome da DLL" },
    { "id": "R006", "enabled": true, "description": "Processo privilegiado carregando DLL não assinada" },
    { "id": "R007", "enabled": true, "description": "Burst: > 3 carregamentos de DLL em 5 segundos" }
  ]
}
```

| Modo | Comportamento |
|---|---|
| `AUDIT` | Todas as DLLs são permitidas; ocorrências são registradas. Use durante a implantação inicial. |
| `ENFORCE` | DLLs com pontuação acima de `0,60` são bloqueadas. |
| `MONITOR_ONLY` | Apenas log; sem bloqueio; mínima sobrecarga. |

### Limiares de Pontuação

| Faixa | Ação |
|---|---|
| `0,00 – 0,30` | `Permitido` |
| `0,31 – 0,60` | `PermitidoFlagged` (registrado como Warning) |
| `0,61 – 0,85` | `Bloqueado` |
| `≥ 0,86` | `BloqueadoSempre` |

### Pesos das Dimensões de Pontuação

| Dimensão | Peso |
|---|---|
| Caminho | 0,40 |
| Hash | 0,25 |
| Assinatura | 0,20 |
| Nome | 0,15 |

### Modificadores de Pontuação

| Condição | Modificador |
|---|---|
| Caminho Tier 1 (System32 / SysWOW64) | `−0,10` (bônus de redução de risco) |
| Carregamento pós-inicialização | `+0,15` de penalidade |
| Hash não encontrado no banco | `+0,10` de penalidade |
| OCSP/CRL indisponível | `+0,05` de penalidade |

### `config/hash_database.json`

```jsonc
{
  "schema_version": 1,
  "entries": [
    {
      "dll_name":     "ntdll.dll",
      "sha256":       "<hex — populado pelo bootstrap_hashdb>",
      "trusted_path": "C:\\\\Windows\\\\System32\\\\ntdll.dll",
      "description":  "DLL da Camada NT"
    }
  ],
  "known_system_dlls": ["ntdll.dll", "kernel32.dll"],
  "revoked": [],
  "db_integrity_hash": "<SHA-256 sobre JSON canônico — definido pelo bootstrap_hashdb>"
}
```

> `sha256` e `db_integrity_hash` ficam vazios até o bootstrapper ser executado. `VerifyHashDatabaseIntegrity` registra um `Warning` na inicialização se estes campos estiverem ausentes, mas não interrompe a inicialização.

---

## Monitoramento em Tempo Real

Dois mecanismos rodam concorrentemente em uma thread dedicada em segundo plano:

### ETW (Rastreamento de Eventos do Windows)

Assina o provedor `Microsoft-Windows-Kernel-Process` e consome eventos `ImageLoad` (ID de Evento 5). Fornece notificação **imediata** em sub-milissegundo quando qualquer DLL é mapeada no espaço de endereço do processo — incluindo injeção externa.

**Requisito:** `SE_SYSTEM_PROFILE_PRIVILEGE`. Se indisponível, o monitor registra `Warning` e recorre apenas ao polling.

### Polling (`EnumProcessModules`)

A cada `monitor_poll_interval_ms` (padrão 5.000 ms), um snapshot completo de módulos é comparado contra a linha de base capturada na inicialização. Módulos ausentes da linha de base disparam `AuditFinding` com severidade `Alert`.

### Recebendo Ocorrências

```cpp
cfg.monitor_callback = [](const dhd::AuditFinding* finding, void* user_data) {
    // finding->issue_code  — ex.: "RUNTIME_INJECTION"
    // finding->dll_path    — caminho completo do módulo detectado
    // finding->severity    — Warning | Alert
    // finding->description — explicação legível por humanos
    MinhaApp::AoDetectarDll(*finding);
};
```

> O callback é disparado na thread em segundo plano do monitor. Deve ser thread-safe e **não deve** chamar `ShutdownDefenseSystem` a partir do próprio callback.

---

## Formato de Log

Eventos são gravados em `<diretório_de_log>\\dhd_<AAAAMMDD>.jsonl` (JSON Lines, um evento por linha, novo arquivo por dia).

```json
{
  "schema":          "dhd/log/v1",
  "timestamp":       "2026-04-23T14:05:32.123Z",
  "pid":             1234,
  "hostname":        "ESTACAO01",
  "process_name":    "minhaapp.exe",
  "severity":        "ALERT",
  "source":          "SECURE_LOADER",
  "dll_path":        "C:\\\\Temp\\\\evil.dll",
  "risk_score":      0.91,
  "action":          "BlockedAlways",
  "block_reasons":   18,
  "risk_level":      "Critical",
  "is_post_startup": true,
  "hmac_sha256":     "a3f9c1..."
}
```

### Integridade HMAC

Cada entrada de log é autenticada com **HMAC-SHA256** usando uma chave de 32 bytes gerada na inicialização e mantida exclusivamente na memória do processo. Qualquer modificação offline em uma linha invalida seu MAC, habilitando detecção de adulteração. A chave é zerada com segurança durante o encerramento.

---

## GUI

`DhdGui.exe` é uma aplicação **WPF .NET 8** (MVVM via CommunityToolkit.Mvvm, tema escuro via ModernWpf, gráficos ao vivo via LiveChartsCore) que consome `DhdBridge.dll` e expõe a API DHD completa através de seis páginas:

| Página | Funcionalidade |
|---|---|
| **Dashboard** | Cartão de saúde do sistema, contador de ocorrências ao vivo, contador de eventos descartados, feed de alertas recentes |
| **Monitor RT** | Série temporal deslizante LiveCharts2 de eventos de detecção; DataGrid de ocorrências com filtro |
| **Validar DLL** | Validação por arquivo com detalhamento de pontuação nas dimensões caminho/hash/assinatura/nome |
| **Audit Scanner** | Scan de diretório ou executável; verificações de DLL fantasma, diretórios graváveis e ACLs; exportação de relatório JSON |
| **Logs** | Navegador de log JSONL com coluna de integridade HMAC, filtros de severidade/fonte/intervalo de data |
| **Configurações** | Configuração de caminhos, intervalo de polling do monitor, ações de endurecimento, bootstrap do banco de hashes |

### Executando a GUI

```powershell
DhdGui\\bin\\Release\\net8.0-windows\\win-x64\\DhdGui.exe
```

> `ijwhost.dll` (do pacote de host .NET 8) deve estar presente ao lado de `DhdBridge.dll` no diretório de saída. É copiada automaticamente durante o passo de build do dotnet.

### Compilando a GUI

```powershell
# Compilar DhdBridge.dll primeiro
msbuild DhdBridge\\DhdBridge.vcxproj /p:Configuration=Release /p:Platform=x64

# Em seguida compilar a GUI
dotnet build DhdGui\\DhdGui.csproj -c Release -r win-x64
```

---

## Modelo de Ameaças

### Dentro do Escopo

| Ameaça | Mitigação |
|---|---|
| DLL hijacking por caminho relativo (ataque CWD) | `SetDefaultDllDirectories` remove CWD da ordem de busca na inicialização |
| DLL fantasma colocada antes de System32 no PATH | Whitelist de caminho + simulação de ordem de busca no `AuditScanner` |
| Spoofing de nome por homoglifo | Normalização Unicode + tabela de homoglifos (R005) |
| Typosquatting (ex.: `kerne132.dll`) | Verificação de distância Levenshtein ≤ 2 contra nomes de DLL do sistema (R004) |
| Injeção de DLL não assinada | Validação Authenticode via `WinVerifyTrust` (R002) |
| DLL conhecida adulterada em disco (troca de hash) | Comparação SHA-256 contra `hash_database.json` bootstrapado |
| Injeção em tempo real pós-inicialização | `RuntimeMonitor` ETW + polling; `Alert` em qualquer módulo ausente da linha de base de inicialização |
| Adulteração de política / banco de dados | `HardenPolicyFile`, `HardenLogDirectory`, `VerifyHashDatabaseIntegrity` na inicialização |
| Adulteração de log / destruição de evidências | HMAC-SHA256 por entrada; chave apenas na memória do processo |
| Injeção em burst (carregamentos rápidos sequenciais) | Regra de detecção de burst R007 — > 3 carregamentos em 5 s dispara `Alert` |

### Fora do Escopo

| Ameaça | Motivo |
|---|---|
| Rootkits em nível de kernel | Requer driver de kernel; controles de modo usuário não conseguem competir |
| Administrador comprometido | Admin pode desabilitar qualquer defesa de modo usuário por design |
| Exploits de formato PE no binário hospedeiro | Fora do escopo de uma biblioteca de defesa no tempo de carregamento de DLL |
| Ataques de canal lateral | Não abordados |

### Limitações Conhecidas

- **ETW requer privilégio.** Sem `SE_SYSTEM_PROFILE_PRIVILEGE`, apenas o polling está ativo. Reduza `monitor_poll_interval_ms` ou conceda o privilégio antecipadamente.
- **O banco de hashes deve ser bootstrapado.** Sem ele, a pontuação por hash é degradada e um `Warning` é registrado na inicialização.
- **OCSP/CRL em ambientes air-gapped.** O modificador `+0,05` é aplicado automaticamente. Desabilite a verificação OCSP na política ou pré-popule dados de revogação.
- **`WinVerifyTrust` é síncrono.** Para caminhos sensíveis à latência, pré-valide DLLs conhecidas boas na inicialização para se beneficiar do cache de validação (`ServedFromCache` em `ValidationResult`).

---

## Referência de Build

### Backend Nativo

```powershell
# Configurar
cmake -B C:\\build\\dhd -S . -G "Visual Studio 17 2022" -A x64

# Compilar Release
cmake --build C:\\build\\dhd --config Release --parallel

# Executar testes unitários
ctest --test-dir C:\\build\\dhd -C Debug --output-on-failure
```

**Artefatos produzidos:**

| Artefato | Localização |
|---|---|
| `shared.lib` | `C:\\build\\dhd\\shared\\Release\\` |
| `core.lib` | `C:\\build\\dhd\\core\\Release\\` |
| `intelligence.lib` | `C:\\build\\dhd\\intelligence\\Release\\` |
| `monitor.lib` | `C:\\build\\dhd\\monitor\\Release\\` |
| `audit.lib` | `C:\\build\\dhd\\audit\\Release\\` |
| `audit_scanner_cli.exe` | `C:\\build\\dhd\\audit\\Release\\` |
| `bootstrap_hashdb.exe` | `C:\\build\\dhd\\tools\\Release\\` |
| `test_*.exe` | `C:\\build\\dhd\\tests\\Release\\` |

### Bridge C++/CLI

```powershell
$msbuild = "C:\\Program Files (x86)\\Microsoft Visual Studio\\2022\\BuildTools\\MSBuild\\Current\\Bin\\amd64\\MSBuild.exe"
& $msbuild DhdBridge\\DhdBridge.vcxproj /p:Configuration=Release /p:Platform=x64 /m /nologo
# Saída: build\\DhdBridge\\Release\\DhdBridge.dll
```

### GUI WPF

```powershell
& "C:\\Program Files\\dotnet\\dotnet.exe" build DhdGui\\DhdGui.csproj -c Release -r win-x64
# Saída: DhdGui\\bin\\Release\\net8.0-windows\\win-x64\\DhdGui.exe
```

---

## Licença

MIT © 2026. Veja [LICENSE](LICENSE) para o texto completo.
"""

out = pathlib.Path(r"C:\Users\Henry\OneDrive\Área de Trabalho\DLL Hijacking\dll-hijack-defense\README.md")
out.write_text(content, encoding="utf-8")
print(f"Escrito: {out.stat().st_size} bytes")
