# Changelog

Todas as mudanças notáveis neste projeto estão documentadas neste arquivo.

O formato é baseado em [Keep a Changelog](https://keepachangelog.com/),
e este projeto adere ao [Semantic Versioning](https://semver.org/).

## [1.0.0] — 2026-04-25

### ✨ Added

#### Backend C++17
- **DefenseSystem** — Fachada principal com 5 camadas de defesa
- **Hardening** — Endurecimento de ordem de busca de DLL (SetDllDirectory, ACLs)
- **DllValidator** — Validação em 4 camadas:
  - Path whitelist (tier-based)
  - Name heuristics (typosquatting detection)
  - SHA-256 hash lookup + database
  - Authenticode signature verification (online + offline via OCSP)
- **RiskAnalyzer** — Análise composta de risco:
  - Entropia de nome
  - Reputação do assinante
  - Anomalias PE (seções, imports)
  - Burst detection
- **LoggingEngine** — Eventos estruturados com HMAC-SHA256:
  - JSON Lines (.jsonl)
  - Flat CSV format
  - Thread-safe async writes
- **RuntimeMonitor** — Monitoramento ETW + polling de diretório:
  - ImageLoad event tracing
  - Directory change notifications
  - Callback system para anomalias
- **AuditScanner** — Scanner offline de dependências:
  - BFS traversal de imports PE
  - Detecção de Phantom DLLs
  - Relatórios JSON estruturados
- **Policy Engine** — Gerenciador de política thread-safe:
  - JSON configuration loading
  - SRWLOCK sincronização
  - Thresholds configuráveis
- **Testes** — GoogleTest suite com:
  - Validação de assinatura
  - Cache behavior
  - Thread-safety
  - Policy logic

#### Frontend WPF .NET 8
- **Dashboard** — Status do sistema + eventos recentes
- **RealtimeMonitor** — Gráficos LiveCharts:
  - Carregamentos por minuto
  - Taxa de bloqueio
  - Indicadores numéricos
- **ValidateDll** — Validador com UI visual:
  - File picker
  - Trust score display
  - Risk level colors
- **AuditScanner** — UI para análise profunda:
  - Executável select
  - Hash database select
  - Progresso em tempo real
  - Tabela de findings com filtros
  - Exportação JSON
- **LogViewer** — Visualizador estruturado:
  - Parse JSON Lines
  - Filtros por severidade/timestamp
  - Busca de texto
- **SettingsPage** — Configuração centralizada:
  - Path validators
  - Bootstrap button (audit_scanner_main)
  - Hardening button (Set-Acls.ps1)
  - Política inline
- **Design** — ModernWpfUI:
  - Temas moderno com Fluent Design
  - Dark/Light mode ready

#### Bridge C++/CLI
- **DhdBridge.dll** — Interop C++/CLI:
  - DefenseSystemBridge static methods
  - ValidationResult marshalling
  - Monitor callback support

#### Ferramentas
- **bootstrap_hashdb.exe** — CLI para popular BD de hashes:
  - Directory scanning recursivo
  - SHA-256 batch computation
  - JSON generation
- **Set-Acls.ps1** — PowerShell script para ACLs:
  - Applica permissões restritivas
  - Modo dry-run
- **Update-HashDatabase.ps1** — Adiciona DLLs personalizadas

#### Documentação
- README.md completo (500+ linhas)
- README_BACKEND.md (technical deep-dive)
- DhdGui/README.md (MVVM + UI guide)
- QUICKSTART.md (5-minute setup)
- CONTRIBUTING.md (contributor guide)
- SECURITY.md (vulnerability disclosure)
- FAQ.md (troubleshooting)
- CHANGELOG.md (this file)
- LICENSE (MIT)
- .gitignore (Windows + .NET + CMake)

#### Configuração
- **policy/defaults.json** — Política padrão:
  - Modo Audit/Strict
  - Thresholds configuráveis
  - Weights para fatores
- **config/hash_database.json** — Banco de hashes SHA-256
- **CMakeLists.txt** — Build system:
  - Suporte a Debug/Release
  - GoogleTest FetchContent
  - MSVC compiler flags

### 🐛 Fixed

#### P0 (Crítico)
- **A-01: Policy Logic Inversion** — DetermineAction() tinha lógica invertida (HIGH trust = bloqueado):
  - Fixo: Inverteu comparações para `score < (1.0 - threshold)`
  - Impacto: Agora HIGH trust realmente = ALLOW

#### P1 (Alto)
- **A-02: OCSP Dead Code** — Branches idênticas, check online nunca executava:
  - Fixo: Flag adicionada apenas quando `!check_revocation_ocsp`
- **A-03: Data Race (Policy)** — GetConfig() retornava referência após SRWLOCK release:
  - Fixo: Mudado para retorno por valor (copy inside lock)
- **A-04: Buffer Overflows** — sprintf_s com 6 MAX_PATH em 2048/4096 buffers:
  - Fixo: audit_scanner.cpp e logging_engine.cpp migrados para std::string
- **A-06/A-07: Dispose() Singleton** — Pages transientes chamavam Dispose() em VM singleton:
  - Fixo: Removidos handlers Unloaded
- **A-08: Deadlock (GUI)** — stdout/stderr lidos sequencialmente (pipe saturation):
  - Fixo: Task.WhenAll() para leitura paralela
  - Componente: SettingsViewModel.RunBootstrapAsync()

#### P2 (Médio)
- **A-09: Cache Hit Race** — s_cache_hits incrementado sob shared lock:
  - Fixo: Incrementado em exclusive lock block
- **A-10: O(n²) Algorithm** — vector::erase(begin()) em BFS:
  - Fixo: Mudado para deque com pop_front() — O(n)
  - Componente: audit_scanner.cpp
- **A-11: Uncaught I/O Exception** — File.WriteAllText() sem try/catch:
  - Fixo: Wrapper try/catch(IOException) com UI feedback
  - Componente: SettingsViewModel.SaveSettings()
- **A-12: Badge Color Bug** — Integridade mostrada verde mesmo em falha:
  - Fixo: Adicionado _hashDbIntegrityOk bool + binding dinâmico
  - Componente: SettingsViewModel + SettingsPage.xaml

### 📊 Build & Testing

- **C++ Backend:**
  - CMake 3.31.6
  - MSVC v143 (Visual Studio 2022)
  - C++17 standard
  - Release build: -O2 -Wall -WX
  - Tests: GoogleTest framework
  
- **C# Frontend:**
  - .NET 8 SDK
  - Target: net8.0-windows10.0.19041
  - Platform: win-x64 only
  - Build: dotnet build -c Release

- **Validation:**
  - ✅ C++ build: 0 errors
  - ✅ C# build: 0 errors, 10 pre-existing NuGet warnings
  - ✅ Tests: 100% suite passes
  - ✅ No security issues detected

---

## Formato de Versioning

Este projeto usa **Semantic Versioning** MAJOR.MINOR.PATCH:
- **MAJOR:** Breaking API changes
- **MINOR:** Novo features (backward-compatible)
- **PATCH:** Bug fixes

---

## Roadmap Futuro

### v1.1 (Q3 2026)
- [ ] CI/CD via GitHub Actions
- [ ] Automated builds para release binaries
- [ ] Extended threat model documentation
- [ ] Performance profiling + optimization
- [ ] Testes de stress (10000+ DLLs)

### v1.2 (Q4 2026)
- [ ] Machine learning for anomaly detection
- [ ] Certificate pinning enhancement
- [ ] Multi-language UI (pt-BR, es-ES, fr-FR, zh-CN)
- [ ] PowerShell module para integração

### v2.0 (2027)
- [ ] Suporte a AppContainers
- [ ] Kernel driver para modo kernel-land
- [ ] Cloud-based reputation API
- [ ] Integração com CrowdStrike/SentinelOne

---

## Notas de Upgrade

### De 0.x para 1.0

Nenhuma versão anterior liberada publicamente (projeto em desenvolvimento privado).

---

## Contribuidores

- **Autor Principal:** [seu-nome]
- **Revisores de Segurança:** [contribuidores]

---

## Como Relatar Bugs

Veja [SECURITY.md](SECURITY.md) para vulnerabilidades críticas.
Para bugs normais, abra [GitHub Issues](https://github.com/seu-usuario/dll-hijack-defense/issues).

---

**Última atualização:** 25 de Abril de 2026
