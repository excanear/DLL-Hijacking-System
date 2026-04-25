# Contribuindo para DLL Hijacking Defense

Obrigado por considerar contribuir! Este documento fornece orientações para participar do projeto.

## 📋 Código de Conduta

Este projeto adere ao [Código de Conduta do Contribuidor](https://www.contributor-covenant.org/).
Todos os participantes devem ser respeitosos e inclusivos.

## 🤔 Antes de Começar

- **Reporte bugs** via GitHub Issues com título descritivo e passos para reproduzir
- **Sugira features** via Discussions antes de começar a trabalhar
- **Leia a documentação** (README.md, backend docs, GUI docs)

## 🔄 Processo de Contribuição

### 1. Fork e Clone

```bash
git clone https://github.com/seu-usuario/dll-hijack-defense.git
cd dll-hijack-defense
git remote add upstream https://github.com/original/dll-hijack-defense.git
```

### 2. Crie uma Branch

```bash
git checkout -b feature/descricao-clara
# ou para bug fixes:
git checkout -b bugfix/numero-issue
```

**Convenção de nome:**
- `feature/nome-da-feature` — Novas funcionalidades
- `bugfix/numero-issue` — Correções
- `docs/descricao` — Documentação
- `test/descricao` — Testes

### 3. Faça Suas Mudanças

#### C++ Backend

```cpp
// ✅ Bom
void ProcessDll(const wchar_t* path) noexcept {
    if (!ValidatePath(path)) {
        LogError(L"Invalid path");
        return;
    }
    // ...
}

// ❌ Evite
void ProcessDll(wchar_t* path) {  // Sem noexcept, sem validação
    // ...
}
```

**Diretrizes C++:**
- C++17 standard, não use C++20 ainda
- `noexcept` onde possível (sem exceções)
- Use `std::wstring` para paths (Unicode)
- RAII para gerenciamento de recursos
- Use `SRWLOCK` para sincronização (não mutexes)

#### C# / MVVM

```csharp
// ✅ Bom
[ObservableProperty]
private string statusMessage = "Pronto";

[RelayCommand]
private async Task ScanAsync(CancellationToken ct) {
    try {
        await _service.ScanAsync(ct);
    }
    catch (OperationCanceledException) {
        StatusMessage = "Cancelado";
    }
}

// ❌ Evite
public string StatusMessage {  // Sem @ObservableProperty
    get { return _status; }
    set { _status = value; NotifyChanged(); }
}
```

**Diretrizes C#:**
- Use `#nullable enable` no topo de novos arquivos
- `async/await` para I/O
- `ObservableProperty` para MVVM
- Sempre `await` em event handlers
- Thread-safe com `lock` ou `Interlocked*`

### 4. Testes

**C++ (GoogleTest):**
```bash
cmake --build build --config Release --target RUN_TESTS
```

**C# (xUnit):**
```bash
dotnet test DhdGui.Tests/DhdGui.Tests.csproj -c Release
```

**Cobertura esperada:**
- Novas features: 80%+ cobertura
- Bug fixes: Teste específico reproduzindo o bug

### 5. Commit com Mensagem Clara

```bash
git add .
git commit -m "feat: adiciona validação de DLL por SHA-256

- Implementa ComputeFileHashSHA256 em dll_validator.cpp
- Adiciona lookup em hash_database.json
- Testes: test_validator.cpp::ComputeHashTest
- Performance: ~30ms por DLL

Closes #123"
```

**Formato Conventional Commits:**
```
type(scope): description

body

footer
```

Tipos: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

### 6. Push e Pull Request

```bash
git fetch upstream
git rebase upstream/main
git push origin feature/nome
```

**No GitHub:**
1. Abra Pull Request com template preenchido
2. Descreva mudanças, razão, testes
3. Link issues relacionadas: `Closes #123`
4. Aguarde review

---

## 📋 Checklist de Pull Request

- [ ] **Código limpo** — Sem console debug, sem TODOs vivos
- [ ] **Tests adicionados** — Novos testes para nova lógica
- [ ] **Tests passam** — `RUN_TESTS` (C++) ou `dotnet test` (C#)
- [ ] **Documentação** — README atualizado se necessário
- [ ] **Sem breaking changes** — API compatível para trás (ou discutido)
- [ ] **Builds localmente** — Release build sem erros
- [ ] **Sem warnings novos** — Nivel 4 warning no MSVC

---

## 🏗️ Diretrizes de Arquitetura

### C++ Backend

```
Responsabilidade por camada:

core/        → Carregamento, validação, loader seguro
intelligence → Análise de risco, logging
monitor      → ETW, polling, callbacks
audit        → Scanner offline, BFS
shared       → Tipos, política, constantes

Dependências: Unidirecional (core ← audit, intelligence ← shared)
Sem ciclos!
```

### C# Frontend

```
MVVM Pattern:

View (XAML)
    ↓
ViewModel (ObservableObject + RelayCommand)
    ↓
Service (IDhdService interface)
    ↓
C++/CLI Bridge (DhdBridge.dll)

Nunca: ViewModels acessando UI diretamente
Sempre: Binding e INotifyPropertyChanged
```

---

## 🔍 Review Esperado

**Revisores procuram por:**

✅ **Segurança:**
- Sem buffer overflows (use `std::string`, não arrays)
- Sem data races (verificar locks)
- Validação de entrada apropriada

✅ **Performance:**
- Sem loops O(n²)
- Cache apropriado (hash, policy)
- Sem alocações em loops críticos

✅ **Testabilidade:**
- Funções injetáveis de dependências
- Sem lógica em constructores

✅ **Legibilidade:**
- Nomes claros
- Comentários onde não óbvio
- Sem código dead

---

## 🐛 Reportando Bugs

**Template de Issue:**

```markdown
## Descrição
Descrição clara do bug.

## Passos para Reproduzir
1. ...
2. ...
3. ...

## Comportamento Esperado
O sistema deveria ...

## Comportamento Atual
O sistema faz ...

## Ambiente
- OS: Windows 10 Build 19041
- Visual Studio: 2022 v17.x
- .NET SDK: 8.0.x

## Stack Trace (se aplicável)
[...]

## Arquivos Relacionados
- core/dll_validator.cpp
- DhdGui/ViewModels/SomeViewModel.cs
```

---

## 💡 Sugerindo Funcionalidades

**Template de Discussion:**

```markdown
## Problema que Resolve
Descrição breve do problema.

## Solução Proposta
Como você resolveria?

## Alternativas Consideradas
Outras abordagens?

## Impacto
- Performance: ...
- Security: ...
- Compatibility: ...
```

---

## 📖 Documentação

### Inline Comments

```cpp
// Para WHY, não WHAT:
// ❌ x = score < 0.14;        // Set x to true if score less than 0.14
// ✅ x = score < 0.14;        // Classify as malicious: score below threshold
```

### XML Comments (C#)

```csharp
/// <summary>
/// Valida arquivo DLL contra base de dados de hashes.
/// </summary>
/// <param name="path">Caminho absoluto do arquivo</param>
/// <returns>true se válido; false se malicioso ou não encontrado</returns>
public bool ValidateDll(string path) { }
```

### README Updates

- Adicione seção em README.md se feature for visível
- Documente exemplos de código
- Atualize tabelas de referência

---

## 🎯 Áreas onde Contribuições São Bem-Vindas

### 🔴 Alta Prioridade

- [ ] CI/CD (.github/workflows)
- [ ] Testes de integração
- [ ] Performance profiling
- [ ] Segurança review

### 🟡 Média Prioridade

- [ ] Documentação adicional
- [ ] Exemplos de código
- [ ] Suporte a mais idiomas de log

### 🟢 Baixa Prioridade

- [ ] UI/UX improvements
- [ ] Temas adicionais
- [ ] Localizações

---

## 📞 Perguntas?

- 💬 **Discussions** — Para ideias abertas
- 🐛 **Issues** — Para bugs e features específicas
- 📧 **Email** — seu-email@exemplo.com

---

## 📜 Licença

Ao contribuir, você concorda que suas contribuições serão licenciadas sob a mesma licença MIT do projeto.

---

**Obrigado por contribuir! 🎉**

