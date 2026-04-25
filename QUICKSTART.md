# 🚀 Quick Start — 5 Minutos

Inicie o **DLL Hijacking Defense System** em 5 passos.

## 1️⃣ Pré-requisitos

✅ Windows 10+ (build 19041)  
✅ Visual Studio 2022 Build Tools  
✅ .NET 8 SDK  
✅ CMake 3.20+  
✅ Git  

**Verificar:**
```powershell
dotnet --version                    # Deve ser 8.0+
cmake --version                     # Deve ser 3.20+
"C:\Program Files\dotnet\dotnet.exe" --version
```

---

## 2️⃣ Clone e Build

```powershell
# Clone
git clone https://github.com/seu-usuario/dll-hijack-defense.git
cd dll-hijack-defense

# Backend C++
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release --parallel

# Frontend .NET
dotnet build DhdGui/DhdGui.csproj -c Release -r win-x64
```

---

## 3️⃣ Popule Banco de Dados de Hashes

```powershell
# System DLLs
.\build\tools\Release\bootstrap_hashdb.exe `
    --directory "C:\Windows\System32" `
    --output "config\hash_database.json" `
    --recursive
```

---

## 4️⃣ (Opcional) Aplique Endurecimento

```powershell
# Como Administrador
Set-ExecutionPolicy RemoteSigned -Scope Process
.\scripts\Set-Acls.ps1 -TargetDirectory "C:\MeuApp"
```

---

## 5️⃣ Execute a GUI

```powershell
.\DhdGui\bin\Release\net8.0-windows\win-x64\DhdGui.exe
```

**Ou via dotnet:**
```powershell
dotnet run --project DhdGui/DhdGui.csproj -c Release
```

---

## ✅ Verificar Funcionamento

1. **Dashboard** aberta? ✔️
2. Clique "Start System" (botão azul) ✔️
3. Navegue para "Validador" ✔️
4. Selecione uma DLL (ex: `C:\Windows\System32\kernel32.dll`) ✔️
5. Score deve aparecer como **verde (baixo risco)** ✔️

---

## 🎯 Próximos Passos

| Objetivo | Ir Para |
|----------|---------|
| Entender a arquitetura | [README.md](README.md) |
| Validar seu app | [AuditScannerPage](DhdGui/README.md#4-auditscanner-page) |
| Configurar política | [SettingsPage](DhdGui/README.md#6-settings-page) |
| Integrar em seu código | [API Reference](README.md#api-de-referência) |
| Contribuir | [CONTRIBUTING.md](CONTRIBUTING.md) |

---

## ❓ Problemas?

### Build falha?
```powershell
# Limpe tudo
Remove-Item -Recurse build
# Recompile
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

### GUI não abre?
```powershell
# Verifique .NET
dotnet --info
# Instale ijwhost
dotnet new console  # Trigger instalação de runtime
```

### Hash database vazio?
```powershell
# Reexecute bootstrap
.\build\tools\Release\bootstrap_hashdb.exe `
    --directory "C:\Windows\System32" `
    --output "config\hash_database.json" `
    --recursive `
    --verbose
```

Veja [FAQ.md](FAQ.md) para mais detalhes.

---

## 🎓 Recursos Recomendados

- **Documentação técnica:** [dll-hijack-defense/README_BACKEND.md](dll-hijack-defense/README_BACKEND.md)
- **GUI documentation:** [DhdGui/README.md](DhdGui/README.md)
- **Modelo de ameaças:** [README.md#modelo-de-ameaças](README.md#modelo-de-ameaças)
- **Perguntas frequentes:** [FAQ.md](FAQ.md)

---

**Pronto!** 🎉  
Você agora tem DefenseSystem rodando.

Para integrar em seu código C++:
```cpp
#include "defense_system.h"

DefenseSystemConfig config{};
config.database_path = "config\\hash_database.json";
config.policy_path = "policy\\defaults.json";
InitializeDefenseSystem(config);

HMODULE h = SecureLoadLibrary(L"minha_dll.dll");
```

Leia [API Reference](README.md#api-de-referência) para mais.

