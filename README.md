<div align="center">

<img src="https://img.shields.io/badge/plataforma-Windows%2010%2B-0078D4?style=for-the-badge&logo=windows&logoColor=white"/>
<img src="https://img.shields.io/badge/C%2B%2B-17-00599C?style=for-the-badge&logo=cplusplus&logoColor=white"/>
<img src="https://img.shields.io/badge/.NET-8.0-512BD4?style=for-the-badge&logo=dotnet&logoColor=white"/>
<img src="https://img.shields.io/badge/build-MSBuild%2017-blueviolet?style=for-the-badge&logo=visualstudio&logoColor=white"/>
<img src="https://img.shields.io/badge/testes-GoogleTest-orange?style=for-the-badge"/>
<img src="https://img.shields.io/badge/licença-MIT-yellow?style=for-the-badge"/>

# Sistema de Defesa contra DLL Hijacking

**Proteção de nível produção, defesa em profundidade contra DLL Hijacking para aplicações Windows 10+.**

Cinco camadas de segurança interligadas — endurecimento da ordem de busca, validação pré-carregamento, pontuação de risco composta, monitoramento em tempo real e auditoria offline — coordenadas por uma fachada C++17 única, expostas via bridge C++/CLI e operadas por uma GUI de gerenciamento WPF completa.

[Arquitetura](#arquitetura) · [Quick Start](#quick-start) · [Referência da API](#referência-da-api) · [Configuração](#referência-de-configuração) · [GUI](#gui) · [Modelo de Ameaças](#modelo-de-ameaças)

</div>

---

## Índice

1. [Visão Geral](#visão-geral)
2. [Arquitetura](#arquitetura)
3. [Pré-requisitos](#pré-requisitos)
4. [Quick Start](#quick-start)
5. [Configuração Inicial](#configuração-inicial)
6. [Implantação](#implantação)
7. [Referência da API](#referência-da-api)
8. [Referência de Configuração](#referência-de-configuração)
9. [Monitoramento em Tempo Real](#monitoramento-em-tempo-real)
10. [Formato de Log](#formato-de-log)
11. [GUI](#gui)
12. [Modelo de Ameaças](#modelo-de-ameaças)
13. [Referência de Build Completa](#referência-de-build-completa)
14. [Contribuindo](#contribuindo)
15. [Licença](#licença)

---

## Visão Geral

DLL Hijacking continua sendo um dos vetores de ataque mais prevalentes no Windows, permitindo que adversários injetem código malicioso disfarçado de bibliotecas legítimas. Este sistema fornece uma solução multicamada que cobre todo o ciclo de vida de uma DLL — do disco ao processo em execução.

| Camada | Módulo | Responsabilidade |
|--------|--------|-----------------|
| 1 – Endurecimento | `core/hardening` | Remove diretórios inseguros da ordem de busca; aplica ACLs restritivas via `Set-Acls.ps1` |
| 2 – Validação Pré-Carregamento | `core/dll_validator` | Verifica assinatura Authenticode, hash SHA-256 contra banco de dados, metadados PE e lista de permissões |
| 3 – Análise de Risco | `intelligence/risk_analyzer` | Pontuação de risco composta (0–100) combinando entropia, reputação do fornecedor, localização e métricas PE |
| 4 – Monitoramento em Tempo Real | `monitor/runtime_monitor` | ETW (Event Tracing for Windows) + polling de diretório; callback configurável ao detectar anomalia |
| 5 – Auditoria | `audit/audit_scanner` | Varredura offline de executáveis; detecta dependências não autorizadas, order-hijackable e sequestráveis |

---

## Arquitetura

### Diagrama de Componentes

```
┌─────────────────────────────────────────────────────────────────┐
│                        DhdGui.exe (.NET 8 WPF)                  │
│  Dashboard · Monitor RT · Validar DLL · Audit Scanner · Logs    │
└────────────────────────────┬────────────────────────────────────┘
                             │ P/Invoke via C++/CLI
┌────────────────────────────▼────────────────────────────────────┐
│                    DhdBridge.dll (C++/CLI .NET 8)               │
│          DefenseSystemBridge · ValidatorBridge · MonitorBridge  │
└────────────────────────────┬────────────────────────────────────┘
                             │ Chamadas nativas
┌────────────────────────────▼────────────────────────────────────┐
│              dll-hijack-defense (C++17 Estático)                │
│                                                                  │
│  ┌────────────┐  ┌──────────────┐  ┌────────────────────────┐  │
│  │    core    │  │ intelligence │  │       monitor          │  │
│  │ hardening  │  │ risk_analyzer│  │   runtime_monitor      │  │
│  │ validator  │  │ logging_eng. │  │   ETW + dir polling    │  │
│  │ sec_loader │  └──────────────┘  └────────────────────────┘  │
│  │ defense_sys│                                                  │
│  └────────────┘  ┌──────────────┐  ┌────────────────────────┐  │
│                  │    audit     │  │        shared          │  │
│                  │ audit_scanner│  │  policy · constants    │  │
│                  └──────────────┘  │  types · utils         │  │
│                                    └────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### Estrutura do Repositório

```
dll-hijack-defense/
├── audit/              # Scanner de auditoria offline
├── config/
│   └── hash_database.json   # BD de hashes SHA-256 confiáveis
├── core/               # Núcleo: hardening, validação, loader seguro, fachada
├── intelligence/       # Motor de logging e analisador de risco
├── monitor/            # Monitor de runtime (ETW + polling)
├── policy/
│   └── defaults.json   # Política de segurança padrão
├── scripts/
│   ├── Set-Acls.ps1         # Aplica ACLs restritivas
│   └── Update-HashDatabase.ps1  # Atualiza BD de hashes
├── shared/             # Tipos, constantes e política compartilhados
├── tests/              # Testes unitários (GoogleTest)
├── tools/
│   └── bootstrap_hashdb.cpp # Ferramenta de bootstrap do BD de hashes
└── CMakeLists.txt
```

### Tabela de Módulos

| Módulo | Tipo | Descrição |
|--------|------|-----------|
| `core` | Biblioteca estática | Fachada principal do sistema (`DefenseSystem`), validador de DLL, loader seguro, endurecimento |
| `intelligence` | Biblioteca estática | Motor de log com HMAC-SHA256, analisador de risco composto |
| `monitor` | Biblioteca estática | Monitor de runtime baseado em ETW e polling de diretório |
| `audit` | Biblioteca estática | Scanner de auditoria com análise de importações PE |
| `shared` | Biblioteca estática | Tipos base, constantes, motor de política JSON |
| `DhdBridge` | DLL C++/CLI | Bridge .NET/nativo para consumo pelo DhdGui |
| `DhdGui` | EXE WPF .NET 8 | Interface gráfica de gerenciamento completa |
| `bootstrap_hashdb` | Executável | Inicializa `hash_database.json` com hashes de DLLs do sistema |

---

## Pré-requisitos

| Dependência | Versão Mínima | Observação |
|-------------|--------------|-----------|
| Windows | 10 (build 19041+) | Obrigatório para ETW APIs utilizadas |
| Visual Studio Build Tools | 2022 (v143) | Com carga de trabalho "Desenvolvimento para desktop com C++" |
| CMake | 3.20+ | Geração de projetos MSBuild |
| .NET SDK | 8.0+ | Para DhdBridge e DhdGui |
| GoogleTest | Automático (FetchContent) | Baixado durante o configure do CMake |

> **Nota:** O projeto compila exclusivamente para **x64**. Compilações x86 ou ARM não são suportadas.

---

## Quick Start

```powershell
# 1. Clone o repositório
git clone https://github.com/seu-usuario/dll-hijack-defense.git
cd dll-hijack-defense

# 2. Configure e compile o backend C++
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release

# 3. Bootstrap do banco de dados de hashes
.\build\tools\Release\bootstrap_hashdb.exe --output config\hash_database.json

# 4. Compile a GUI
dotnet build DhdGui\DhdGui.csproj -c Release

# 5. Execute
.\DhdGui\bin\Release\net8.0-windows\win-x64\DhdGui.exe
```

---

## Configuração Inicial

### 1. Banco de Dados de Hashes

O banco de dados de hashes SHA-256 é o núcleo da camada de validação. Populá-lo antes da implantação é obrigatório:

```powershell
# Gera hashes das DLLs do sistema em C:\Windows\System32
.\build\tools\Release\bootstrap_hashdb.exe `
    --directory "C:\Windows\System32" `
    --output "config\hash_database.json" `
    --recursive

# Adiciona DLLs do seu aplicativo
.\scripts\Update-HashDatabase.ps1 `
    -AppDirectory "C:\MeuAplicativo" `
    -DatabasePath "config\hash_database.json"
```

### 2. Endurecimento de ACLs

```powershell
# Aplica permissões restritivas nos diretórios críticos
# Requer privilégio de Administrador
.\scripts\Set-Acls.ps1 -TargetDirectory "C:\MeuAplicativo" -Verbose
```

---

## Implantação

### Passo 1 — Build completo

```powershell
cmake -B build -G "Visual Studio 17 2022" -A x64 `
      -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release --parallel
dotnet publish DhdGui\DhdGui.csproj -c Release -r win-x64 --self-contained false
```

### Passo 2 — Banco de dados de hashes

```powershell
.\build\tools\Release\bootstrap_hashdb.exe `
    --directory "C:\Windows\System32" `
    --output "config\hash_database.json"
```

### Passo 3 — Hardening de ACL

```powershell
# Executar como Administrador
Set-ExecutionPolicy RemoteSigned -Scope Process
.\scripts\Set-Acls.ps1 -TargetDirectory "C:\MeuAplicativo"
```

### Passo 4 — Auditoria pré-implantação

```powershell
.\build\audit\Release\audit_scanner_main.exe `
    --target "C:\MeuAplicativo\meu_app.exe" `
    --database "config\hash_database.json" `
    --report "audit_report.json"
```

### Passo 5 — Integração no código do aplicativo

```cpp
#include "defense_system.h"

int main() {
    DefenseSystemConfig config{};
    config.database_path     = "config\\hash_database.json";
    config.policy_path       = "policy\\defaults.json";
    config.enable_etw        = true;
    config.enable_monitoring = true;

    if (!InitializeDefenseSystem(config)) {
        // Falha crítica — abortar
        return 1;
    }

    // Substituir LoadLibrary por SecureLoadLibrary em todo o código
    HMODULE hMod = SecureLoadLibrary(L"minha_dll.dll");

    // ... lógica do aplicativo ...

    ShutdownDefenseSystem();
    return 0;
}
```

---

## Referência da API

### `InitializeDefenseSystem`

```cpp
bool InitializeDefenseSystem(const DefenseSystemConfig& config);
```

Inicializa todas as cinco camadas de defesa na ordem correta. Deve ser chamada **antes** de qualquer `SecureLoadLibrary`.

**Parâmetros de `DefenseSystemConfig`:**

| Campo | Tipo | Padrão | Descrição |
|-------|------|--------|-----------|
| `database_path` | `std::string` | `""` | Caminho para `hash_database.json` |
| `policy_path` | `std::string` | `""` | Caminho para `defaults.json` |
| `enable_etw` | `bool` | `true` | Ativa rastreamento ETW |
| `enable_monitoring` | `bool` | `true` | Ativa monitor de diretório em tempo real |
| `log_directory` | `std::string` | `"logs"` | Diretório de saída dos logs |
| `max_risk_score` | `uint32_t` | `60` | Score máximo permitido (0–100) |

**Retorno:** `true` em sucesso; `false` se qualquer camada falhar na inicialização.

---

### `ShutdownDefenseSystem`

```cpp
void ShutdownDefenseSystem();
```

Encerra ordenadamente o monitor de runtime, fecha handles ETW e libera recursos. Deve ser chamada na saída do processo.

---

### `SecureLoadLibrary`

```cpp
HMODULE SecureLoadLibrary(const wchar_t* dll_name);
```

Substituto seguro para `LoadLibrary`/`LoadLibraryEx`. Executa a pipeline completa de validação antes de carregar a DLL.

**Pipeline interna:**
1. Resolve o caminho absoluto usando a lista de diretórios endurecida
2. Verifica assinatura Authenticode
3. Valida hash SHA-256 contra o banco de dados
4. Calcula score de risco; bloqueia se `> max_risk_score`
5. Registra o evento de carregamento no log com HMAC-SHA256
6. Chama `LoadLibraryExW` com `LOAD_WITH_ALTERED_SEARCH_PATH`

**Retorno:** Handle válido ou `nullptr` se bloqueado. Consulte os logs para diagnóstico.

---

### `GetSystemStatus`

```cpp
SystemStatus GetSystemStatus();
```

Retorna snapshot do estado atual do sistema.

```cpp
struct SystemStatus {
    bool     is_initialized;
    uint64_t dlls_loaded_total;
    uint64_t dlls_blocked_total;
    uint64_t findings_count;
    double   average_risk_score;
    bool     monitor_active;
};
```

---

## Referência de Configuração

### `policy/defaults.json`

```json
{
  "enforcement_mode": "enforce",
  "max_risk_score": 60,
  "require_authenticode": true,
  "require_hash_match": true,
  "blocked_directories": [
    "C:\\Windows\\Temp",
    "%TEMP%",
    "%APPDATA%"
  ],
  "allowed_vendor_prefixes": [
    "Microsoft Corporation",
    "Google LLC"
  ],
  "log_rotation_max_mb": 50,
  "log_retention_days": 30,
  "etw_session_name": "DhdDefenseSession"
}
```

**Modos de `enforcement_mode`:**

| Valor | Comportamento |
|-------|--------------|
| `"audit"` | Registra violações, mas **não** bloqueia carregamentos |
| `"warn"` | Registra e exibe alerta, mas não bloqueia |
| `"enforce"` | Bloqueia e registra qualquer DLL que viole a política |

**Limiares de score de risco:**

| Intervalo | Classificação | Ação padrão |
|-----------|--------------|-------------|
| 0–30 | Baixo | Permitido |
| 31–60 | Médio | Permitido (com log) |
| 61–80 | Alto | Bloqueado em modo `enforce` |
| 81–100 | Crítico | Sempre bloqueado |

### `config/hash_database.json`

```json
{
  "version": 2,
  "generated_at": "2026-04-24T00:00:00Z",
  "entries": [
    {
      "name": "kernel32.dll",
      "sha256": "a1b2c3d4...",
      "size_bytes": 1245184,
      "vendor": "Microsoft Corporation",
      "last_verified": "2026-04-24T00:00:00Z"
    }
  ]
}
```

---

## Monitoramento em Tempo Real

O `RuntimeMonitor` combina dois mecanismos complementares:

### ETW (Event Tracing for Windows)

Assina o provider `Microsoft-Windows-Kernel-File` para capturar eventos de criação e renomeação de arquivo em tempo real, sem polling. Requer elevação de privilégios.

### Polling de Diretório

Mecanismo de fallback baseado em `ReadDirectoryChangesW` para diretórios monitorados configurados na política. Funciona sem privilégios elevados.

### Callback de Anomalia

```cpp
void SetAnomalyCallback(std::function<void(const AnomalyEvent&)> callback);

struct AnomalyEvent {
    std::wstring  dll_path;
    AnomalyType   type;       // NEW_DLL, MODIFIED_DLL, DELETED_DLL, HIGH_RISK
    uint32_t      risk_score;
    std::wstring  timestamp;
};
```

---

## Formato de Log

Todos os eventos são gravados em JSON Lines (`.jsonl`) com integridade garantida por HMAC-SHA256:

```json
{
  "timestamp": "2026-04-24T12:34:56.789Z",
  "event_type": "DLL_LOAD_BLOCKED",
  "dll_path": "C:\\Temp\\malicious.dll",
  "risk_score": 87,
  "reason": "HIGH_RISK_SCORE|HASH_MISMATCH|UNTRUSTED_LOCATION",
  "process_id": 4812,
  "thread_id": 1024,
  "hmac_sha256": "f4a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1"
}
```

**Campos de integridade:**
- `hmac_sha256`: HMAC-SHA256 do payload JSON com chave derivada por sessão. Detecta adulteração de logs.

**Rotação de logs:**
- Arquivo rotacionado quando atingir `log_rotation_max_mb` (padrão: 50 MB)
- Arquivos mais antigos que `log_retention_days` (padrão: 30 dias) são removidos automaticamente
- Formato do nome: `dhd_YYYYMMDD_HHMMSS.jsonl`

---

## GUI

A interface gráfica `DhdGui.exe` é construída com WPF .NET 8, ModernWPF UI e Live Charts.

### Dashboard

Painel principal com cards de status em tempo real:
- DLLs carregadas / bloqueadas na sessão
- Score de risco médio
- Status do monitor (ativo/inativo)
- Gráfico de tendência de carregamentos (últimas 24h)

### Monitor em Tempo Real

Feed ao vivo de eventos capturados pelo `RuntimeMonitor`:
- Filtro por tipo de evento (LOAD, BLOCK, ANOMALY)
- Colorização por nível de risco
- Exportação do feed para CSV

### Validar DLL

Ferramenta de análise pontual:
1. Selecione um arquivo `.dll` via diálogo de arquivo
2. O sistema executa toda a pipeline de validação
3. Exibe relatório detalhado: hash, assinatura, score de risco, campos PE, veredicto final

### Audit Scanner

Auditoria completa de um executável:
1. Selecione o `.exe` alvo
2. Configure opções: profundidade de recursão, verificação de assinatura, threshold de risco
3. Visualize findings categorizados: SAFE, WARNING, CRITICAL
4. Exporte relatório em JSON

### Visualizador de Logs

- Navega pelos arquivos `.jsonl` de log
- Filtra por `event_type`, `risk_score`, intervalo de data
- Verifica integridade HMAC de cada entrada
- Destaque visual para eventos bloqueados

### Configurações

- Editor de `policy/defaults.json` com validação em tempo real
- Gerenciador do banco de dados de hashes: adicionar, remover e verificar entradas
- Configurações de conexão com o backend nativo

---

## Modelo de Ameaças

### Em Escopo

| Vetor | Camada de Mitigação |
|-------|-------------------|
| DLL Planting — diretório de trabalho | Hardening (Camada 1) + Validação (Camada 2) |
| DLL Sideloading — diretório do aplicativo | Hash DB (Camada 2) + Score de risco (Camada 3) |
| Substituição de DLL do sistema | Authenticode (Camada 2) + ETW (Camada 4) |
| DLL Proxying | Análise PE (Camada 2) + Score de risco (Camada 3) |
| Novos arquivos em diretórios monitorados | RuntimeMonitor (Camada 4) |
| DLLs não autorizadas em binários existentes | Audit Scanner (Camada 5) |

### Fora de Escopo

- Ataques que exigem acesso físico à máquina
- Exploits de kernel ou drivers maliciosos (requer Secure Boot + HVCI)
- Adulteração de memória em processo já em execução (requer CFG/CET)
- Ataques contra o próprio `DhdGui.exe` ou `DhdBridge.dll`

### Limitações Conhecidas

- O monitoramento ETW requer privilégios elevados (administrador)
- O banco de dados de hashes deve ser atualizado após patches do Windows (use `Update-HashDatabase.ps1`)
- O modo `audit` não fornece proteção ativa — use apenas para diagnóstico
- Assinaturas Authenticode auto-assinadas são rejeitadas por padrão (configurável)

---

## Referência de Build Completa

### Targets CMake

```powershell
# Listar todos os targets disponíveis
cmake --build build --target help

# Build de targets individuais
cmake --build build --target DhdCore     --config Release
cmake --build build --target DhdIntel    --config Release
cmake --build build --target DhdMonitor  --config Release
cmake --build build --target DhdAudit    --config Release
cmake --build build --target DhdShared   --config Release
cmake --build build --target bootstrap_hashdb --config Release
cmake --build build --target audit_scanner_main --config Release

# Build completo paralelo
cmake --build build --config Release --parallel
```

### Executar Testes

```powershell
# Todos os testes
ctest --test-dir build -C Release --output-on-failure

# Testes específicos
ctest --test-dir build -C Release -R "TestValidator" --output-on-failure
ctest --test-dir build -C Release -R "TestRiskAnalyzer" --output-on-failure
ctest --test-dir build -C Release -R "TestPolicy" --output-on-failure
```

### Build da GUI

```powershell
# Debug
dotnet build DhdGui\DhdGui.csproj -c Debug

# Release self-contained
dotnet publish DhdGui\DhdGui.csproj `
    -c Release `
    -r win-x64 `
    --self-contained true `
    -p:PublishSingleFile=true `
    -o publish\

# Copiar DhdBridge.dll manualmente se necessário
Copy-Item build\DhdBridge\Release\DhdBridge.dll `
          DhdGui\bin\Release\net8.0-windows\win-x64\
```

---

## Contribuindo

Contribuições são bem-vindas. Por favor:

1. Faça um fork do repositório
2. Crie uma branch descritiva: `git checkout -b feature/nova-camada`
3. Escreva testes para qualquer nova funcionalidade
4. Garanta que `ctest` passe sem falhas
5. Abra um Pull Request com descrição detalhada

**Guia de estilo C++:** Siga o [C++ Core Guidelines](https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines). Sem exceções em código de caminho crítico; use `std::expected` ou códigos de erro.

---

## Licença

Este projeto está licenciado sob a [Licença MIT](LICENSE).

---

<div align="center">
<sub>Construído com C++17 · .NET 8 · WPF · CMake · MSBuild · GoogleTest</sub>
</div>
