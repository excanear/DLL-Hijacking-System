# DLL Hijacking Defense — Backend C++17

**Núcleo de segurança em C++17 puro — 5 camadas de validação e monitoramento.**

## 📑 Índice Rápido

- [Estrutura de Módulos](#estrutura-de-módulos)
- [Pipeline de Validação](#pipeline-de-validação)
- [Compilação](#compilação)
- [Testes](#testes)
- [Arquitetura Interna](#arquitetura-interna)

---

## 📁 Estrutura de Módulos

### `core/` — Núcleo de Defesa

#### `defense_system.cpp/h`
Fachada principal que coordena todas as 5 camadas.

**Responsabilidades:**
- Inicialização ordenada de módulos
- Gerenciamento de estado global
- Exposição de API pública (`InitializeDefenseSystem`, `ShutdownDefenseSystem`, `SecureLoadLibrary`)

**Funcionalidades-chave:**
- Carregamento de configuração JSON (`policy/defaults.json`)
- Inicialização do banco de dados de hashes
- Início de monitor de runtime ETW
- Cache thread-safe de validações

---

#### `dll_validator.cpp/h`
**4 camadas de validação:**

| Layer | Função | Input | Output |
|-------|--------|-------|--------|
| **1** | `CheckPathWhitelist` | Caminho absoluto | Trust score (0.0–1.0) baseado em tier |
| **2** | `CheckNameHeuristics` | Nome do arquivo | Score por heurística de nome |
| **3** | `ComputeFileHashSHA256` | Handle do arquivo | SHA-256 + lookup em BD |
| **4** | `VerifyAuthenticode` | Assinatura digital PE | Validação de certificado + revogação |

**Cache:**
- Chave: `{canonical_path, mtime}`
- TTL: 1 hora (configurável)
- Thread-safe via SRWLOCK compartilhado

---

#### `hardening.cpp/h`
Endurecimento de ordem de busca de DLL.

**Aplicações:**
```cpp
SetDllDirectoryW(NULL);           // Remove diretórios adicionados
RemoveDirectoryFromPath(...);     // Remove específicos (temp, etc.)
SetDefaultDllDirectories(...);    // Força apenas sistema + app
```

**Scripts de suporte:** `scripts/Set-Acls.ps1`

---

#### `secure_loader.cpp/h`
Wrapper seguro em torno de `LoadLibraryEx`.

**Pipeline:**
1. Resolve caminho absoluto via `GetFinalPathNameByHandleW`
2. Abre arquivo com `CreateFileW` (snapshot imutável)
3. Valida canônico antes vs. durante carregamento (TOCTOU prevention)
4. Chama `ValidateDLL` completo
5. Carrega com `LoadLibraryEx` + flags seguras

---

### `intelligence/` — Análise e Logging

#### `risk_analyzer.cpp/h`
Análise composta de risco com 6+ heurísticas.

**Fatores:**
- Entropia de nome (detecção de ofuscação)
- Reputação do assinante de certificado
- Localização geográfica do arquivo
- Anomalias em metadados PE (seções, imports)
- Burst detection (múltiplas DLLs suspeitas em curto período)
- Baseline anomalies (comparação com histórico)

**Saída:** `RiskLevel` (Low, Medium, High, Critical) + detalhes

---

#### `logging_engine.cpp/h`
Engine de logging com assinatura HMAC-SHA256.

**Formatos:**
- **JSON Lines** (estruturado, com timestamp ISO-8601)
- **Flat CSV** (legível, com pipe `|` delimitador)

**Segurança:**
- Cada evento é assinado com HMAC-SHA256 (chave em memória)
- Carimbo de hora imutável
- Impossível modificar logs sem invalidar HMAC

**Campos:**
```json
{
  "timestamp": "2026-04-25T14:32:11.456Z",
  "severity": "BLOCKED",
  "dll_path": "C:\\malware.dll",
  "trust_score": 0.08,
  "risk_level": "Critical",
  "process_id": 1234,
  "action": "BlockedAlways",
  "hmac_sha256": "deadbeef..."
}
```

---

### `monitor/` — Runtime Monitoring

#### `runtime_monitor.cpp/h`
Monitoramento híbrido ETW + diretório.

**Fontes de eventos:**
1. **ETW (Event Tracing for Windows)** — `ImageLoad` events de kern
2. **Directory polling** — Detecção de arquivo novo/modificado

**Callbacks:**
- Quando DLL potencialmente perigosa é detectada
- Sem overhead em modo AUDIT (log apenas)
- Bloqueio imediato em modo STRICT (aborta carregamento)

---

### `audit/` — Auditoria Offline

#### `audit_scanner_main.cpp`
Scanner de linha de comando para auditoria profunda.

**Análises:**
- Busca em profundidade de todos os executáveis em diretório
- Parsing de imports PE completo (IAT + DLT)
- Detecção de vulnerabilidades de hijacking:
  - **Phantom DLLs** — Imports sem arquivo correspondente
  - **Writable directories** — DLL em local gravável
  - **ACL permissivo** — Permissões insuficientes
  - **Search order issues** — Ordem de busca insegura

**Saída:** JSON com findings estruturados

```bash
audit_scanner_main.exe \
  --target C:\MyApp.exe \
  --database config\hash_database.json \
  --report audit_report.json \
  --recursive
```

---

### `shared/` — Tipos e Política Compartilhados

#### `policy.cpp/h`
Motor de política JSON thread-safe.

**Responsabilidades:**
- Carregamento de `defaults.json`
- Gerenciamento de estado thread-safe (SRWLOCK)
- Funções de consulta (`IsPathInWhitelist`, `GetConfig`, `DetermineAction`)

**Configuração:**
```json
{
  "mode": "Strict",                      // Audit ou Strict
  "enable_logging": true,
  "check_revocation_ocsp": true,
  "cache_enabled": true,
  "cache_ttl_seconds": 3600,
  
  "threshold_block_always": 0.86,        // Bloqueia sempre se score > 0.86
  "threshold_block_strict": 0.61,        // Bloqueia em Strict se score > 0.61
  "threshold_allow": 0.30,               // Aviso se score entre 0.30–0.70
  
  "modifier_tier1_bonus": 0.10,
  "modifier_post_startup_penalty": -0.15,
  "modifier_hash_unknown_penalty": -0.10,
  
  "weight_path": 0.40,
  "weight_name": 0.15,
  "weight_hash": 0.25,
  "weight_signature": 0.20
}
```

#### `constants.h`
Constantes globais compiladas.

---

#### `types.h`
Definições de tipos principais.

```cpp
enum class LoadAction { Allowed, AllowedFlagged, Blocked, BlockedAlways };
enum class RiskLevel { Low, Medium, High, Critical };
struct ValidationResult { LoadAction action; RiskLevel risk; float trust_score; ... };
```

---

## 🔄 Pipeline de Validação

### Fluxo Completo (`ValidateDLL`)

```
1. Arquivo Existe?
   └─ Não → Retorna Falha
   
2. Resolve Caminho Absoluto
   └─ Usa GetFinalPathNameByHandleW para snapshot imutável
   
3. Camada 1 — Whitelist Path
   ├─ Tier1 (System32) → Score 1.0
   ├─ Tier2 (Program Files) → Score 1.0
   ├─ Tier3 (AppDir) → Score 0.8
   └─ Nenhum → Score 0.0
   
4. Camada 2 — Name Heuristics
   ├─ Typosquatting detection (Levenshtein)
   └─ Ofuscação (entropia)
   
5. Camada 3 — Hash SHA-256
   ├─ Lookup em hash_database.json
   ├─ Encontrado → Score 1.0
   ├─ Não encontrado → Score 0.0
   └─ Revogado → Score -0.1
   
6. Camada 4 — Authenticode
   ├─ Assinado com certificado confiável → Score 1.0
   ├─ Assinado com certificado suspeito → Score 0.5
   └─ Sem assinatura → Score 0.0
   
7. Análise de Risco Composta
   ├─ Pontuação agregada com pesos
   ├─ Anomalias PE (seções, imports)
   └─ Burst detection
   
8. Decisão Final (DetermineAction)
   ├─ Score < 0.14 → BlockedAlways
   ├─ Score 0.14–0.39 (Strict) → Blocked
   ├─ Score 0.39–0.70 → AllowedFlagged (com warning)
   └─ Score > 0.70 → Allowed
```

### Semântica de Score

**0.0 = Completamente desconfiável / malicioso**
**1.0 = Completamente confiável / clean**

O pipeline inverte os thresholds internamente:
- `score < (1.0 - threshold)` → bloqueia
- `score >= (1.0 - threshold)` → permite

---

## 🔨 Compilação

### Configuração (CMake)

```powershell
# Debug com símbolos completos
cmake -B build_dbg -G "Visual Studio 17 2022" -A x64 `
      -DCMAKE_BUILD_TYPE=Debug `
      -DBUILD_TESTING=ON

# Release otimizado
cmake -B build -G "Visual Studio 17 2022" -A x64 `
      -DCMAKE_BUILD_TYPE=Release
```

### Build

```powershell
# Build tudo
cmake --build build --config Release --parallel 8

# Build específico
cmake --build build --config Release --target audit_scanner_main
cmake --build build --config Release --target bootstrap_hashdb
```

### Outputs

```
build/
├── core/Release/          # DLL estática core.lib
├── intelligence/Release/  # DLL estática intelligence.lib
├── monitor/Release/       # DLL estática monitor.lib
├── audit/Release/         # DLL estática audit.lib
├── audit/Release/
│   └── audit_scanner_main.exe    # CLI executável
├── tools/Release/
│   └── bootstrap_hashdb.exe      # Ferramenta de bootstrap
└── tests/Release/
    ├── test_validator.exe
    ├── test_policy.exe
    └── ...
```

---

## 🧪 Testes

### Executar Testes

```powershell
# Via CMake (após build)
cmake --build build --config Release --target RUN_TESTS

# Diretamente com CTest
cd build
ctest -C Release --output-on-failure -V
```

### Cobertura

Testes cobrem:
- ✅ Validação de assinatura (legítima, revogada, malformada)
- ✅ Hash database lookup (encontrado, não encontrado, corrompido)
- ✅ Name heuristics (typosquatting, ofuscação)
- ✅ Risk analyzer (burst detection, anomalias PE)
- ✅ Policy loading e thread-safety
- ✅ Cache behavior (hit, miss, expiration)

---

## 🏛️ Arquitetura Interna

### Sincronização

**Mecanismos:**
- `SRWLOCK` para operações leitura-pesada (policy, cache)
- `InterlockedXX` para contadores (hits, misses)
- `DispatcherTimer` em GUI para polling seguro

**Garantias:**
- Nenhuma deadlock potencial
- Leitura sempre retorna snapshot atômico
- Escrita via exclusive lock

### Tratamento de Erros

**Estratégia:**
- `noexcept` onde possível (validação, logging)
- Return codes para falhas não-fatais
- `__try/__except` para PE parsing malformado

**Nenhuma exceção C++ lançada pelo backend C++.**

### Estrutura de Memória

```
Inicialização:
  ├─ Config (~1 KB)
  ├─ Hash DB (~50–100 MB em memória)
  ├─ Policy (~10 KB)
  ├─ Validation Cache (~50 MB para 1000 entradas)
  └─ ETW session handle (~4 KB)
  
Runtime:
  └─ Monitor de diretório (~1 KB por thread)
```

---

## 📊 Performance

### Validação

| Operação | Tempo | Notas |
|----------|-------|-------|
| Cache hit | ~1 ms | Retorno instantâneo |
| Novo arquivo | 50–200 ms | Hash SHA-256 + Authenticode |
| Assinado + no BD | ~30 ms | Sem Authenticode |
| Sem assinatura | ~100 ms | Verificação Authenticode |

### Monitoramento

- **ETW overhead:** ~2–5% CPU (idle)
- **Polling overhead:** ~1% CPU por thread
- **Callback latência:** <10ms para processamento

---

## 🔗 Integração com C#/GUI

### Bridge C++/CLI

`DhdBridge.dll` expõe:
```csharp
public class DefenseSystemBridge {
    public static bool Initialize(string dbPath, string policyPath) { ... }
    public static ValidationResult ValidateDll(string path) { ... }
    public static void RegisterMonitorCallback(Action<MonitorFinding> cb) { ... }
}
```

### Chamadas Principais

```csharp
// GUI → Backend via P/Invoke
var result = DefenseSystemBridge.ValidateDll("C:\\app.dll");
Debug.WriteLine($"Trust Score: {result.TrustScore}");
```

---

## 📖 Leitura Adicional

- [MSDN: DLL Search Order](https://docs.microsoft.com/en-us/windows/win32/dlls/dll-search-order)
- [OWASP: DLL Hijacking](https://owasp.org/www-community/attacks/Path_Traversal)
- [Microsoft: Authenticode](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/authenticode)
- [Windows ETW Documentation](https://docs.microsoft.com/en-us/windows/win32/etw/about-event-tracing)

