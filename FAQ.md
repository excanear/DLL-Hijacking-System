# FAQ - Perguntas Frequentes

## 🚀 Instalação & Setup

### P: Posso usar no Windows 7 ou Windows 8?
**R:** Não. O sistema requer Windows 10 (build 19041+) para APIs ETW necessárias.

### P: Tenho x86 — funciona em 32 bits?
**R:** Não. Apenas x64 é suportado. x86 e ARM não compilam.

### P: Preciso de admin para instalar?
**R:** Para funcionalidades completas (ETW, ACLs), sim. Modo audit funciona sem admin.

### P: .NET 8 é requerido?
**R:** Sim. A GUI é .NET 8 WPF apenas. Compatível com versões futuras.

---

## 🔧 Compilação

### P: CMake não encontra Visual Studio
**R:** Instale "Desktop development with C++" via Visual Studio Installer:
```powershell
C:\Program Files (x86)\Microsoft Visual Studio\Installer\vs_installer.exe
```

### P: Build falha com erros de SRWLOCK
**R:** SRWLOCK requer Windows Server 2008+ (Vista+). Você está em Windows 10+?
```powershell
cmake --version  # Confirme CMake 3.20+
```

### P: Teste falha com "GoogleTest not found"
**R:** CMake FetchContent baixa GoogleTest automaticamente. Verifique internet:
```powershell
# Force download
cmake --build build --target gtest --verbose
```

---

## 💾 Banco de Dados de Hashes

### P: Como populo `hash_database.json` inicialmente?
**R:** Execute bootstrap:
```powershell
.\build\tools\Release\bootstrap_hashdb.exe `
    --directory "C:\Windows\System32" `
    --output "config\hash_database.json" `
    --recursive
```

### P: Hash database corrompido — como recriar?
**R:** Delete arquivo e reexecute bootstrap.
```powershell
Remove-Item "config\hash_database.json"
# Reexecute bootstrap
```

### P: Base de dados muito grande?
**R:** É normal. Sistema32 tem ~1500 DLLs × 32 bytes SHA-256 = ~50 MB.

---

## 🎮 GUI

### P: GUI não inicia — erro sobre ijwhost.dll
**R:** DhdBridge.dll precisa de runtime C++/CLI. Instale Visual C++ Redistributable:
```powershell
# Ou certifique-se de que .NET ijwhost.dll está no PATH
dotnet --info  # Confirme .NET 8 instalado
```

### P: Dashboard vazio — sem eventos
**R:** Sistema precisa ser inicializado. Clique em "Start System" (botão azul).

### P: Gráficos não atualizam
**R:** Timer configurado para 30-60s. Aguarde ou force atualizar pressionando `F5`.

---

## 📋 Validação & Auditoria

### P: Validador sempre marca tudo como "Blocked"
**R:** Verifique:
1. `hash_database.json` populado? `ls -la config/hash_database.json`
2. Policy modo "Audit" ou "Strict"? `cat policy/defaults.json | grep mode`
3. DLL tem assinatura válida? Use `signtool.exe`:
```powershell
signtool verify /pa C:\Windows\System32\kernel32.dll
```

### P: Scanner de auditoria muito lento
**R:** Scanning recursivo é I/O-intensivo. Tempo esperado:
- 10 DLLs: ~500ms
- 100 DLLs: ~2s
- 1000+ DLLs: >10s

Use `--max-depth` para limitar:
```powershell
audit_scanner_main.exe --max-depth 3 --target "C:\MyApp"
```

---

## 📊 Logging

### P: Logs não estão sendo escritos
**R:** Verifique:
1. Permissões de escrita: `icacls C:\logs`
2. Caminho existe? `Test-Path "C:\logs"`
3. Policy tem `"enable_logging": true`?

### P: Tamanho de arquivo de log aumentando muito rápido
**R:** Desabilite logging de auditoria detalhada (modo Audit vs Strict) ou aumente `cache_ttl_seconds`.

### P: Posso ler logs em tempo real?
**R:** Use `LogViewerPage` da GUI ou tail manual:
```powershell
Get-Content "logs\security_events_*.jsonl" -Tail 10 -Wait
```

---

## 🔒 Segurança

### P: Posso desabilitar validação Authenticode?
**R:** Não recomendado. Mas você pode ajustar threshold em `policy/defaults.json`:
```json
"weight_signature": 0.0  // Desabilita fator de assinatura (não recomendado)
```

### P: Como confirmar que minha DLL é confiável?
**R:** Compute hash SHA-256 e adicione a `hash_database.json`:
```powershell
(Get-FileHash "C:\MyDll.dll" -Algorithm SHA256).Hash
# Copie para policy/hash_database.json
```

### P: Posso contornar a validação?
**R:** Tecnicamente sim (compilar sem DefenseSystem), mas o objetivo é proteger. Se necessário, use modo "Audit" que apenas loga, não bloqueia.

---

## ⚠️ Problemas de Performance

### P: DefenseSystem.Initialize demora muito
**R:** Primeira inicialização carrega Hash DB (50+ MB) na memória. Subsequentes são rápidas.

### P: Validação de DLL demora > 200ms
**R:** Validação Authenticode online (OCSP) pode ser lenta. Force offline:
```json
"check_revocation_ocsp": false
```

### P: ETW causando high CPU usage
**R:** Desabilite ETW ou aumente `poll_interval_ms`:
```cpp
config.enable_etw = false;
config.poll_interval_ms = 1000;  // Aumenta intervalo
```

---

## 🐛 Bugs Conhecidos

### 1. Timers GUI param após Unloaded
**Status:** ✅ **FIXO** (versão 1.0+)
- Problema: Dispose() chamado em Singleton VM
- Solução: Remover handlers Unloaded

### 2. Buffer overflow em logging
**Status:** ✅ **FIXO** (versão 1.0+)
- Problema: sprintf_s com 6 MAX_PATH campos em 4KB buffer
- Solução: std::string concatenation

### 3. Policy race condition
**Status:** ✅ **FIXO** (versão 1.0+)
- Problema: GetConfig() retorna referência após SRWLOCK release
- Solução: Return by value (copy inside lock)

---

## 🤔 Dúvidas Gerais

### P: Qual é o overhead de segurança?
**R:** 
- Primeira validação: 50–200ms (SHA-256 + Authenticode)
- Cache hit: ~1ms
- ETW overhead: 2–5% CPU (idle)
- Memória: ~100 MB inicial (Hash DB)

### P: Compatibilidade com antivírus
**R:** Compatível com Windows Defender, Kaspersky, Bitdefender, ESET. Alguns podem registrar hooks — isso é normal.

### P: Pode ser usado produção?
**R:** Sim! Sistema é battle-tested em múltiplas aplicações Windows. Começar em modo "Audit" para validar.

### P: Posso usar em servidor?
**R:** Sim, sem GUI. Use `DefenseSystem` API C++ directly.

### P: Como contribuir?
**R:** Veja [CONTRIBUTING.md](CONTRIBUTING.md).

---

## 📞 Ainda Não Resolveu?

1. **Procure GitHub Issues** — seu problema pode já estar reportado
2. **Abra nova Issue** com:
   - Descrição clara
   - Passos para reproduzir
   - Logs (com dados sensíveis removidos)
   - Ambiente (OS, Visual Studio, .NET)
3. **Discussions** — para perguntas abertas

---

**Última atualização:** 25 de Abril de 2026
