<div align="center">

![DLL Hijacking Defense]()

<img src="https://img.shields.io/badge/plataforma-Windows%2010%2B-0078D4?style=for-the-badge&logo=windows&logoColor=white"/>
<img src="https://img.shields.io/badge/C%2B%2B-17-00599C?style=for-the-badge&logo=cplusplus&logoColor=white"/>
<img src="https://img.shields.io/badge/.NET-8.0-512BD4?style=for-the-badge&logo=dotnet&logoColor=white"/>
<img src="https://img.shields.io/badge/WPF-Modern%20UI-E05A00?style=for-the-badge&logo=windows&logoColor=white"/>
<img src="https://img.shields.io/badge/build-CMake%2B%2BMSBuild-blueviolet?style=for-the-badge&logo=visualstudio&logoColor=white"/>
<img src="https://img.shields.io/badge/tests-GoogleTest-orange?style=for-the-badge"/>
<img src="https://img.shields.io/badge/license-MIT-brightgreen?style=for-the-badge"/>

# 🛡️ DLL Hijacking Defense System

**Defesa em profundidade, nível produção contra DLL Hijacking — 5 camadas de segurança interligadas**

Proteção completa de ciclo de vida: endurecimento de ordem de busca, validação pré-carregamento com Authenticode + SHA-256, pontuação de risco composta, monitoramento em tempo real via ETW, e auditoria offline offline.

[🚀 Quick Start](#quick-start) · [📐 Arquitetura](#arquitetura) · [📚 Documentação](#documentação) · [🔧 Configuração](#configuração) · [🎮 GUI](#gui-de-gerenciamento)

</div>

---

## 📖 Índice

- [Visão Geral](#visão-geral)
- [Arquitetura](#arquitetura)
- [Pré-requisitos](#pré-requisitos)
- [Quick Start](#quick-start)
- [Construindo o Projeto](#construindo-o-projeto)
- [Configuração](#configuração)
- [Implantação](#implantação)
- [API de Referência](#api-de-referência)
- [GUI de Gerenciamento](#gui-de-gerenciamento)
- [Logging](#logging)
- [Modelo de Ameaças](#modelo-de-ameaças)
- [FAQ](#faq)
- [Contribuindo](#contribuindo)
- [Licença](#licença)

---

## 🎯 Visão Geral

### Por que isto importa?

DLL Hijacking permanece como um dos vetores de ataque mais eficazes contra aplicações Windows:
- **Sem privilégios necessários** — Adversários exploram ordem de busca padrão
- **Implantação trivial** — Criar arquivo malicioso com nome certo em diretório acessível
- **Execução com privilégio completo** — DLL carregada roda no contexto do processo pai
- **Bypass de antivírus** — Muitas soluções focam apenas no executável, não em dependências

### Solução multicamada

| Camada | Responsabilidade | Mecanismo |
|--------|------------------|-----------|
| **1️⃣ Endurecimento** | Remove diretórios inseguros da ordem de busca | `SetDllDirectory(NULL)` + ACLs via PowerShell |
| **2️⃣ Validação** | Verifica assinatura + hash + metadata PE antes de carregar | Authenticode + SHA-256 + base de dados confiável |
| **3️⃣ Análise de Risco** | Atribui pontuação 0–100 baseada em múltiplas heurísticas | Entropia, reputação, localização, formato PE |
| **4️⃣ Monitoramento** | Detecta anomalias em tempo real durante execução | ETW + polling de diretório com callbacks |
| **5️⃣ Auditoria** | Analisa offline dependências e vulnerabilidades | BFS de importações, detecção de order-hijacking |

---

## 📐 Arquitetura

### Visão de Componentes

```
┌─────────────────────────────────────────────────────────────────┐
│                    DhdGui.exe (.NET 8 WPF)                      │
│              Dashboard | Monitor | Validator | Audit | Logs     │
└────────────────────────┬────────────────────────────────────────┘
                         │ P/Invoke
┌────────────────────────▼────────────────────────────────────────┐
│                 DhdBridge.dll (C++/CLI .NET 8)                  │
│     DefenseSystemBridge | ValidatorBridge | MonitorBridge      │
└────────────────────────┬────────────────────────────────────────┘
                         │ Interop
┌────────────────────────▼────────────────────────────────────────┐
│           dll-hijack-defense (C++17 + STL)                      │
│                                                                  │
│  ┌──────────────┐   ┌─────────────────┐   ┌─────────────────┐  │
│  │ core/        │   │ intelligence/   │   │ monitor/        │  │
│  │ • hardening  │   │ • risk_analyzer │   │ • runtime_      │  │
│  │ • validator  │   │ • logging_engine│   │   monitor       │  │
│  │ • sec_loader │   └─────────────────┘   │ • ETW + polling │  │
│  │ • defense_   │                         └─────────────────┘  │
│  │   system     │   ┌──────────────┐   ┌─────────────────────┐│
│  └──────────────┘   │ audit/       │   │ shared/             ││
│                     │ • audit_     │   │ • policy/constants  ││
│                     │   scanner    │   │ • types             ││
│                     └──────────────┘   └─────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

### Estrutura do Repositório

```
dll-hijack-defense/
├── 📁 audit/                    # Scanner de auditoria offline
│   ├── audit_scanner.cpp        # Implementação do scanner
│   ├── audit_scanner.h
│   └── audit_scanner_main.cpp   # Ponto de entrada CLI
├── 📁 config/
│   └── hash_database.json       # BD de hashes SHA-256 confiáveis
├── 📁 core/                     # Núcleo do sistema
│   ├── defense_system.cpp       # Fachada principal
│   ├── dll_validator.cpp        # 4 camadas de validação
│   ├── hardening.cpp            # Endurecimento de ordem de busca
│   └── secure_loader.cpp        # Loader seguro
├── 📁 intelligence/             # Análise e logging
│   ├── logging_engine.cpp       # Motor de logs com HMAC-SHA256
│   └── risk_analyzer.cpp        # Análise de risco composta
├── 📁 monitor/                  # Monitor de runtime
│   └── runtime_monitor.cpp      # ETW + polling de diretório
├── 📁 policy/
│   └── defaults.json            # Política de segurança padrão
├── 📁 scripts/
│   ├── Set-Acls.ps1             # Aplica permissões restritivas
│   └── Update-HashDatabase.ps1  # Atualiza banco de dados
├── 📁 shared/                   # Tipos e políticas compartilhados
│   ├── constants.h              # Constantes e thresholds
│   ├── policy.cpp/h             # Motor de política JSON
│   └── types.h                  # Tipos base
├── 📁 tests/                    # Testes unitários (GoogleTest)
│   ├── test_validator.cpp
│   ├── test_policy.cpp
│   └── ...
├── 📁 tools/
│   └── bootstrap_hashdb.cpp     # Inicializa BD de hashes
├── 📁 DhdGui/                   # GUI WPF .NET 8
│   ├── Views/                   # Páginas de interface
│   ├── ViewModels/              # Lógica de apresentação
│   ├── Services/                # Serviços de aplicação
│   └── DhdGui.csproj
├── 📁 DhdBridge/                # Bridge C++/CLI
│   └── DhdBridge.csproj
├── CMakeLists.txt
└── README.md (este arquivo)
```

---

## ✅ Pré-requisitos

| Dependência | Versão | Notas |
|-------------|--------|-------|
| **Windows** | 10 (build 19041+) | Requerido para APIs ETW |
| **Visual Studio** | 2022 Build Tools (v143) | C++ Desktop Workload |
| **CMake** | 3.20+ | Geração de projetos MSBuild |
| **.NET SDK** | 8.0+ | Para DhdBridge e DhdGui |
| **GoogleTest** | Automático | Baixado via FetchContent |

> ⚠️ **Apenas x64** — Compilações x86 ou ARM não são suportadas.

---

## 🚀 Quick Start

### Windows PowerShell

```powershell
# 1. Clone e navegue
git clone https://github.com/seu-usuario/dll-hijack-defense.git
cd dll-hijack-defense

# 2. Backend C++ (Release)
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release --parallel

# 3. Bootstrap de hashes do sistema
.\build\tools\Release\bootstrap_hashdb.exe `
    --directory "C:\Windows\System32" `
    --output "config\hash_database.json" `
    --recursive

# 4. GUI WPF
dotnet build DhdGui\DhdGui.csproj -c Release -r win-x64

# 5. Execute!
.\DhdGui\bin\Release\net8.0-windows\win-x64\DhdGui.exe
```

---

## 🔨 Construindo o Projeto

### Compilação Completa

```powershell
# Configure
cmake -B build -G "Visual Studio 17 2022" -A x64 `
      -DCMAKE_BUILD_TYPE=Release `
      -DBUILD_TESTING=ON

# Compile
cmake --build build --config Release --parallel 8

# Testes
cmake --build build --config Release --target RUN_TESTS
```

### Compilação Apenas da GUI

```powershell
cd DhdGui
dotnet build DhdGui.csproj -c Release -r win-x64
dotnet publish DhdGui.csproj -c Release -r win-x64 --self-contained false
```

### Debug Build (com símbolos)

```powershell
cmake -B build_dbg -G "Visual Studio 17 2022" -A x64 `
      -DCMAKE_BUILD_TYPE=Debug
cmake --build build_dbg --config Debug
```

---

## ⚙️ Configuração

### 1. Banco de Dados de Hashes

O banco de dados SHA-256 é essencial — popule antes de implantação:

```powershell
# Hashes de DLLs do sistema
.\build\tools\Release\bootstrap_hashdb.exe `
    --directory "C:\Windows\System32" `
    --output "config\hash_database.json" `
    --recursive `
    --verbose

# Adicione suas DLLs
.\scripts\Update-HashDatabase.ps1 `
    -AppDirectory "C:\MeuApp" `
    -DatabasePath "config\hash_database.json" `
    -Verbose
```

### 2. Política de Segurança

Edite `policy/defaults.json`:

```json
{
  "mode": "Strict",
  "enable_logging": true,
  "check_revocation_ocsp": true,
  "cache_enabled": true,
  "cache_ttl_seconds": 3600,
  "block_always": 0.86,
  "block_strict": 0.61,
  "allow_threshold": 0.30,
  "tier1_bonus": 0.10,
  "post_startup_penalty": -0.15
}
```

### 3. ACLs Restritivas (Opcional)

```powershell
# Executar como Administrador
.\scripts\Set-Acls.ps1 `
    -TargetDirectory "C:\MeuApp" `
    -RestrictedUsers "Administrators" `
    -Verbose
```

---

## 📦 Implantação

### Checklist de Pré-Implantação

- [ ] Backend C++ compilado (Release)
- [ ] `hash_database.json` populado com hashes do seu aplicativo
- [ ] `policy/defaults.json` configurado
- [ ] ACLs aplicadas via `Set-Acls.ps1`
- [ ] Auditoria executada e revisada
- [ ] Testes completos executados

### Passo a Passo

```powershell
# 1. Build completo
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release

# 2. Prepare database
.\build\tools\Release\bootstrap_hashdb.exe `
    --directory "C:\Windows\System32" `
    --output "config\hash_database.json"

# 3. Hardening
Set-ExecutionPolicy RemoteSigned -Scope Process
.\scripts\Set-Acls.ps1 -TargetDirectory "C:\MeuApp"

# 4. Auditoria pré-deploy
.\build\audit\Release\audit_scanner_main.exe `
    --target "C:\MeuApp\app.exe" `
    --database "config\hash_database.json" `
    --report "pre_deploy_audit.json"

# 5. Integração no código do seu app
# (Ver seção Integração de Código abaixo)
```

### Integração de Código

```cpp
#include "defense_system.h"
#include <cstdio>

int main() {
    // Configure o sistema
    DefenseSystemConfig config{};
    config.database_path      = "config\\hash_database.json";
    config.policy_path        = "policy\\defaults.json";
    config.log_directory      = "logs";
    config.enable_etw         = true;
    config.enable_monitoring  = true;

    // Initialize
    if (!InitializeDefenseSystem(config)) {
        fprintf(stderr, "[FATAL] Falha ao inicializar DefenseSystem\n");
        return 1;
    }

    // ✅ Use SecureLoadLibrary em vez de LoadLibrary
    HMODULE hMyDll = SecureLoadLibrary(L"minha_dll.dll");
    if (!hMyDll) {
        fprintf(stderr, "[ERROR] Falha ao carregar minha_dll.dll\n");
        ShutdownDefenseSystem();
        return 1;
    }

    // Resto da lógica do aplicativo...

    FreeLibrary(hMyDll);
    ShutdownDefenseSystem();
    return 0;
}
```

---

## 📚 API de Referência

### Inicialização

#### `InitializeDefenseSystem(const DefenseSystemConfig& config) → bool`

Inicializa todas as 5 camadas de defesa. **Deve ser chamado antes de qualquer `SecureLoadLibrary`.**

```cpp
struct DefenseSystemConfig {
    std::string database_path;           // hash_database.json
    std::string policy_path;             // defaults.json
    std::string log_directory;           // Saída de logs
    bool enable_etw;                     // Ativa rastreamento ETW
    bool enable_monitoring;              // Ativa monitor de runtime
    uint32_t poll_interval_ms;           // Intervalo de polling (padrão: 500ms)
};
```

**Retorno:** `true` = sucesso; `false` = falha em qualquer camada.

---

#### `ShutdownDefenseSystem() → void`

Encerra ordenadamente o monitor, fecha handles ETW e libera recursos. Chamar na saída do processo.

---

### Carregamento Seguro

#### `SecureLoadLibrary(const wchar_t* dll_name) → HMODULE`

Substituto de `LoadLibrary`. Pipeline completa de validação antes de carregar.

**Pipeline interna:**
1. Resolve caminho absoluto (ordem de busca endurecida)
2. Valida assinatura Authenticode
3. Computa SHA-256 e valida contra banco de dados
4. Análise de risco de metadados PE
5. Carrega via `LoadLibraryEx` seguro

**Retorno:** Handle válido ou `NULL` se falhar validação.

---

### Validação Manual

#### `ValidateDLL(const wchar_t* dll_path) → ValidationResult`

Valida DLL sem carregar. Útil para auditoria ou pré-checagem.

```cpp
struct ValidationResult {
    dhd::LoadAction action;           // BlockedAlways, Blocked, AllowedFlagged, Allowed
    dhd::RiskLevel risk_level;        // Critical, High, Medium, Low
    float trust_score;                // 0.0–1.0
    std::wstring block_reasons;       // Máscara de bits com razões
    bool served_from_cache;
};
```

---

### Monitoramento em Tempo Real

#### `RegisterMonitorCallback(MonitorCallback cb) → bool`

Registra callback para anomalias detectadas durante runtime.

```cpp
using MonitorCallback = std::function<void(const MonitorFinding&)>;

struct MonitorFinding {
    std::wstring dll_path;
    dhd::LoadAction action;
    float trust_score;
    dhd::RiskLevel risk_level;
    DWORD process_id;
    uint64_t timestamp;
};
```

---

## 🎮 GUI de Gerenciamento

### Funcionalidades

| Aba | Função |
|-----|--------|
| **Dashboard** | Resumo de carregamentos bloqueados, eventos recentes, status do sistema |
| **Monitor** | Gráficos em tempo real de atividade (cargas/min, taxa de bloqueio) |
| **Validador** | Validar arquivo DLL individual com UI visual |
| **Scanner de Auditoria** | Analisa executável e dependências; exporta relatório JSON |
| **Visualizador de Logs** | Painel de logs estruturados com filtros |
| **Configurações** | Política, caminho de BD, caminho de logs |

### Capturas de Tela

*(Em construção — adicione imagens PNG aqui)*

---

## 📋 Logging

### Formatos

#### Flat-file (CSV com timestamp)

```
2026-04-25T14:32:10.123Z | INFO | system initialized
2026-04-25T14:32:11.456Z | BLOCK | C:\Temp\evil.dll scored 0.12 (Critical)
```

#### Structured JSON (por linha)

```json
{
  "schema_version": 1,
  "timestamp": "2026-04-25T14:32:11.456Z",
  "severity": "BLOCKED",
  "dll_path": "C:\\Temp\\evil.dll",
  "trust_score": 0.12,
  "risk_level": "Critical",
  "process_name": "MyApp.exe",
  "process_id": 1234,
  "action": "BlockedAlways",
  "block_reasons": "0x00000001"
}
```

### Localização

```
logs/
├── security_events_YYYY-MM-DD.jsonl      # Eventos estruturados
├── security_events_YYYY-MM-DD.csv        # Flat file
└── crash.log                              # Erros e stack traces
```

---

## 🎯 Modelo de Ameaças

### Ameaças Mitigadas

| Ameaça | Mecanismo | Camada |
|--------|-----------|--------|
| **Search Order Hijacking** | Remove diretórios inseguros; força `SetDllDirectory(NULL)` | 1 |
| **DLL Replacement** | Validação Authenticode + SHA-256 + base de dados confiável | 2 |
| **Side-loading** | Detecção de dependências inesperadas; bloqueio por análise de risco | 3 |
| **Zero-day DLL** | Análise heurística (entropia, formato PE, anomalias) | 3 |
| **Post-load Attacks** | Monitoramento em tempo real via ETW + callbacks | 4 |
| **Evasão de Detecção** | Auditoria offline de toda árvore de dependências | 5 |

### Ameaças Fora do Escopo

- **Corrupção de memória de processo** — Foco apenas no carregamento de DLL
- **Code injection pós-execução** — Monitor não fornece proteção contra hooks
- **Bypass de validação de kernel** — Escopo de usuário apenas

---

## ❓ FAQ

**P: Qual é o overhead de performance?**
R: Validação (~50–200ms por DLL), cache em memória reduz a ~1ms após. ETW overhead é ~2–5% de CPU em ocioso.

**P: Compatibilidade com frameworks?**
R: Funciona com qualquer aplicativo C/C++ Windows; requer integração de código para usar `SecureLoadLibrary`.

**P: Funciona com DLLs de linguagens gerenciadas (.NET)?**
R: Sim — validação ocorre antes do loader, não importa o conteúdo da DLL.

**P: Pode ser burlado?**
R: Não sem modificar o executável ou contornar ACLs do sistema. Detecção de burla registra no log.

---

## 🤝 Contribuindo

Contribuições são bem-vindas! Por favor:

1. **Fork** o repositório
2. **Crie branch** para sua feature (`git checkout -b feature/minha-feature`)
3. **Commit** suas mudanças (`git commit -am 'Adiciona feature incrível'`)
4. **Push** para o branch (`git push origin feature/minha-feature`)
5. **Abra Pull Request** com descrição clara

### Diretrizes de Estilo

- **C++:** C++17, sem exceções (RAII com `noexcept` preferido)
- **C#:** .NET 8, nullable reference types, async/await
- **Tests:** GoogleTest (C++), xUnit (C#)

---

## 📄 Licença

Este projeto é licenciado sob a **Licença MIT** — veja [LICENSE](LICENSE) para detalhes.

```
MIT License

Copyright (c) 2026 DLL Hijacking Defense Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
...
```

---

## 📞 Suporte

- **Issues:** [GitHub Issues](https://github.com/seu-usuario/dll-hijack-defense/issues)
- **Discussões:** [GitHub Discussions](https://github.com/seu-usuario/dll-hijack-defense/discussions)
- **Email:** seu-email@exemplo.com

---

## 🙏 Agradecimentos

- [Microsoft Windows Security](https://docs.microsoft.com/en-us/windows/security/)
- [GoogleTest](https://github.com/google/googletest)
- [Modern WPF UI](https://github.com/Kinnara/ModernWpf)
- [LiveChartsCore](https://github.com/beto-rodriguez/LiveCharts2)

---

<div align="center">

**Feito com ❤️ para segurança Windows.**

⭐ **Se este projeto foi útil, considere dar uma estrela!**

</div>
