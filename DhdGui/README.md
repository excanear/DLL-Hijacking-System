# DhdGui — Interface de Gerenciamento WPF

**GUI moderna em .NET 8 WPF para gerenciamento, monitoramento e auditoria do DLL Hijacking Defense System.**

## 🎨 Visão Geral

DhdGui fornece uma interface unificada para:
- ✅ **Dashboard** — Status do sistema, eventos recentes, estatísticas
- ✅ **Monitor em Tempo Real** — Gráficos de carregamentos por minuto, taxa de bloqueio
- ✅ **Validador de DLL** — Testar arquivo individual com análise visual
- ✅ **Scanner de Auditoria** — Analisa executável + árvore de dependências
- ✅ **Visualizador de Logs** — Logs estruturados com filtros avançados
- ✅ **Configurações** — Política, caminhos, integração com bootstrap

---

## 📑 Índice Rápido

- [Arquitetura](#arquitetura)
- [Compilação](#compilação)
- [Estrutura de Pastas](#estrutura-de-pastas)
- [Páginas (Views)](#páginas-views)
- [ViewModels](#viewmodels)
- [Serviços](#serviços)
- [MVVM Pattern](#mvvm-pattern)
- [Temas e Estilos](#temas-e-estilos)

---

## 🏗️ Arquitetura

### Stack Tecnológico

| Camada | Tecnologia | Versão |
|--------|-----------|--------|
| Framework | .NET | 8.0+ |
| UI | WPF | Integrado .NET 8 |
| MVVM | CommunityToolkit.Mvvm | 8.3.2+ |
| Design | ModernWpfUI | 0.9.6+ |
| Charts | LiveChartsCore | 2.0+ |
| Bridge nativa | DhdBridge.dll | C++/CLI |

### Padrão MVVM

```
View (XAML)
    ↓ Binding (INotifyPropertyChanged)
ViewModel (RelayCommand + ObservableProperty)
    ↓ Interop / P/Invoke
Service (IDhdService)
    ↓
DhdBridge.dll (C++/CLI)
    ↓
dll-hijack-defense (C++17 nativo)
```

### Fluxo de Dados

```
MainWindow.xaml
├── DashboardPage.xaml → DashboardViewModel
├── RealtimeMonitorPage.xaml → RealtimeMonitorViewModel
├── AuditScannerPage.xaml → AuditScannerViewModel
├── ValidateDllPage.xaml → ValidateDllViewModel
├── LogViewerPage.xaml → LogViewerViewModel
└── SettingsPage.xaml → SettingsViewModel

↓ (Data Context)

DhdService (IDhdService)
    ├─ Initialize(policyPath, dbPath, logDir)
    ├─ ValidateDll(path)
    ├─ RunAuditScan(options)
    ├─ StartMonitor(callback)
    └─ GetRecentEvents()

↓ (P/Invoke)

DhdBridge.dll
    └─ DefenseSystemBridge (métodos públicos estáticos)

↓ (Interop)

dll-hijack-defense.lib
```

---

## 📁 Estrutura de Pastas

```
DhdGui/
├── 📄 App.xaml                      # Recursos globais, ThemeResources
├── 📄 App.xaml.cs                   # OnStartup, OnExit, DI setup
├── 📄 DhdGui.csproj                 # Projeto C#, target frameworks
├── 📄 MainWindow.xaml               # Shell da aplicação
├── 📄 MainWindow.xaml.cs            # Navigation logic
│
├── 📁 Views/                        # XAML Pages (UI)
│   ├── DashboardPage.xaml           # Resumo + eventos recentes
│   ├── RealtimeMonitorPage.xaml     # Gráficos em tempo real
│   ├── AuditScannerPage.xaml        # Auditoria de executáveis
│   ├── ValidateDllPage.xaml         # Validação de arquivo único
│   ├── LogViewerPage.xaml           # Visualizador estruturado
│   ├── SettingsPage.xaml            # Configurações
│   └── ...xaml.cs                   # Code-behind (mínimo)
│
├── 📁 ViewModels/                   # Lógica de apresentação
│   ├── DashboardViewModel.cs        # Timer 30s, RefreshAsync()
│   ├── RealtimeMonitorViewModel.cs  # Chart updates, 60s refresh
│   ├── AuditScannerViewModel.cs     # Scan logic + BFS
│   ├── ValidateDllViewModel.cs      # File picker + validation
│   ├── LogViewerViewModel.cs        # Log file loading + filtering
│   ├── SettingsViewModel.cs         # Path validation + bootstrap
│   └── MainViewModel.cs             # (obsoleto, consolidado em Pages)
│
├── 📁 Services/                     # Camada de serviço
│   ├── IDhdService.cs               # Interface de façade
│   ├── DhdService.cs                # Implementação (P/Invoke)
│   ├── LogFileReader.cs             # Parse logs estruturados
│   └── NavigationService.cs         # (obsoleto, dead code)
│
├── 📁 Converters/                   # Value Converters
│   └── SharedConverters.cs          # BoolToColorConverter, etc.
│
├── 📁 Models/                       # Data Transfer Objects
│   ├── ValidationResultModel.cs
│   ├── AuditFindingModel.cs
│   ├── MonitorFindingModel.cs
│   └── LogEventModel.cs
│
├── 📁 Resources/                    # Recursos XAML
│   └── SharedResources.xaml         # Estilos, brushes, converters
│
└── 📁 Migrations/                   # (N/A — sem BD)
```

---

## 🖼️ Páginas (Views)

### 1. DashboardPage

**Responsabilidade:** Resumo do sistema, status, eventos recentes.

**Componentes:**
- Status do sistema (inicializado, ativo, logs)
- Estatísticas (total bloqueado, hoje)
- Tabela de eventos recentes (últimos 100)
- Botões: Iniciar Sistema, Parar Sistema, Limpar Logs

**Binding:**
```xaml
<TextBlock Text="{Binding StatusText}" />
<ItemsControl ItemsSource="{Binding RecentEvents}" />
```

**Timer:** `DispatcherTimer` 30s → `RefreshAsync()`

---

### 2. RealtimeMonitorPage

**Responsabilidade:** Gráficos em tempo real de atividade.

**Componentes:**
- Gráfico de linhas: Carregamentos por minuto (últimas 30 min)
- Gráfico de barras: Taxa de bloqueio por política
- Indicadores numéricos: Total hoje, Bloqueados hoje, Taxa

**Tecnologia:** LiveChartsCore com SkiaSharp rendering

**Thread-safety:**
```csharp
private readonly object _chartLock = new();

lock (_chartLock) {
    _seriesValues.Add(newValue);
}
```

---

### 3. ValidateDllPage

**Responsabilidade:** Validar arquivo individual + análise visual.

**Fluxo:**
1. Usuário seleciona DLL (Browse botão)
2. Valida assinatura, hash, score
3. Exibe resultado visual (verde/amarelo/vermelho baseado em score)

**Outputs:**
```
Score: 0.85 (vermelho)
Status: ✘ Bloqueado
Razão: Score crítico
Recomendação: Verificar origem
```

---

### 4. AuditScannerPage

**Responsabilidade:** Auditoria profunda de executável.

**Fluxo:**
1. Seleciona executável (Browse)
2. Seleciona BD de hashes (Browse)
3. Clica "Scan"
4. Exibe progresso
5. Resultados em tabela filtrada + exporta JSON

**Filtros:**
- Por severidade (Critical, High, Medium, Low)
- Por tipo de issue (Phantom DLL, Writable Dir, ACL, etc.)

---

### 5. LogViewerPage

**Responsabilidade:** Visualização estruturada de logs.

**Componentes:**
- ComboBox de arquivos de log disponíveis
- Tabela com colunas: Timestamp, Severity, DLL, Score, Action
- Filtros: Por severidade, por período, busca por texto

**Thread-safety:**
```csharp
await _reader.ReadLogFileAsync(filePath);
```

---

### 6. SettingsPage

**Responsabilidade:** Configuração de caminhos, política e bootstrap.

**Seções:**
- **Paths:** Policy file, Hash DB, Log directory (Browse buttons)
- **Bootstrap:** Botão para executar `bootstrap_hashdb.exe`
- **Hardening:** Botão para `Set-Acls.ps1`
- **Save:** Botão persiste em `appsettings.json`

**Validação:** Todos os paths verificados antes de save.

---

## 🎯 ViewModels

Cada ViewModel implementa `INotifyPropertyChanged` via `ObservableProperty`.

### Exemplo: DashboardViewModel

```csharp
public partial class DashboardViewModel : ObservableObject, IDisposable {
    [ObservableProperty] private string statusText = "Iniciando...";
    [ObservableProperty] private ObservableCollection<LogEventModel> recentEvents;
    
    private DispatcherTimer _timer;
    
    public DashboardViewModel(IDhdService dhd, ILogFileReader logReader) {
        _dhd = dhd;
        _logReader = logReader;
        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(30) };
        _timer.Tick += OnTimerTick;
    }
    
    [RelayCommand]
    public void SetLogDirectory(string dir) {
        _logDirectory = dir;
        if (!_timer.IsEnabled)
            _timer.Start();
    }
    
    private async void OnTimerTick(object sender, EventArgs e) {
        await RefreshAsync();
    }
    
    public void Dispose() {
        _timer?.Stop();
        _timer?.Tick -= OnTimerTick;
    }
}
```

### Convenção: RelayCommand

```csharp
[RelayCommand]
private async Task ScanAsync() { ... }
// Auto-gera: public IAsyncRelayCommand ScanCommand { get; }
```

---

## 🔧 Serviços

### IDhdService (Interface)

```csharp
public interface IDhdService {
    bool Initialize(string policyPath, string dbPath, string logDir, uint pollMs);
    bool ValidateDll(string path, out ValidationResultModel result);
    (List<AuditFindingModel>, AuditSummaryModel) RunAuditScan(ScanOptionsModel options, CancellationToken ct);
    bool StartMonitor(Action<MonitorFindingModel> callback);
    void StopMonitor();
    IEnumerable<LogEventModel> GetRecentEvents(int count = 100);
}
```

### DhdService (Implementação)

```csharp
public class DhdService : IDhdService {
    private readonly DhdBridgeFacade _bridge = new();
    private Action<MonitorFindingModel>? _monitorCallback;
    private readonly object _monitorLock = new();
    
    public bool StartMonitor(Action<MonitorFindingModel> callback) {
        lock (_monitorLock) {
            _monitorCallback = callback;
            return DhdBridgeFacade.StartMonitor(m => {
                var model = MonitorFindingModel.FromManaged(m);
                Action<MonitorFindingModel>? cb;
                lock (_monitorLock)
                    cb = _monitorCallback;
                cb?.Invoke(model);
            });
        }
    }
}
```

**Thread-safety:** Lock em `_monitorCallback` para evitar data race com `StopMonitor`.

---

## 🎨 MVVM Pattern

### Property Changed

```csharp
[ObservableProperty]
private string myProperty = "initial";

// Auto-gera:
// - Campo privado `_myProperty`
// - Property pública `MyProperty`
// - Chamadas para `OnPropertyChanged("MyProperty")`
```

### Relay Commands

```csharp
[RelayCommand]
private void MyCommand(string parameter) { }

// Auto-gera:
// - IRelayCommand MyCommandCommand { get; }
```

### Async Commands

```csharp
[RelayCommand]
private async Task ScanAsync(CancellationToken ct) {
    try {
        await _dhd.RunAuditScanAsync(options, ct);
    }
    catch (OperationCanceledException) { }
}

// Auto-gera:
// - IAsyncRelayCommand ScanAsyncCommand { get; }
```

---

## 🎨 Temas e Estilos

### Recursos Globais (App.xaml)

```xaml
<ResourceDictionary>
    <Color x:Key="PrimaryColor">#0078D4</Color>
    <SolidColorBrush x:Key="PrimaryBrush" Color="{StaticResource PrimaryColor}" />
    
    <!-- Estilos padrão -->
    <Style TargetType="Button" BasedOn="{StaticResource ModernButtonStyle}" />
    
    <!-- Converters -->
    <local:BoolToColorConverter x:Key="BoolToLockColor" />
</ResourceDictionary>
```

### ModernWpfUI

Componentes padrão reutilizáveis:
- `ui:Button` — Botões modernos
- `ui:TextBlock` — Tipografia
- `ui:CommandBar` — Barra de ferramentas
- `ui:ProgressRing` — Indicador de progresso

### Virtualização

```xaml
<ItemsControl ItemsSource="{Binding Events}"
              VirtualizingPanel.IsVirtualizing="True"
              VirtualizingPanel.VirtualizationMode="Recycling" />
```

---

## 🔄 Ciclo de Vida

### Application Startup

```
App.OnStartup()
  ├─ ConfigureServices (DI container)
  │   ├─ AddSingleton<DashboardViewModel>()
  │   ├─ AddSingleton<RealtimeMonitorViewModel>()
  │   ├─ AddSingleton<IDhdService, DhdService>()
  │   └─ ...
  ├─ DhdService.Initialize(...)
  ├─ DashboardViewModel.SetLogDirectory(...)
  └─ MainWindow.Show()
```

### Application Shutdown

```
App.OnExit()
  ├─ RealtimeMonitorViewModel.Dispose() (timers parados)
  ├─ DashboardViewModel.Dispose()
  ├─ DhdService.StopMonitor()
  └─ _host.Dispose() (libera DI)
```

---

## 🐛 Debugging

### Logs de Debug

```csharp
Debug.WriteLine($"[SettingsViewModel] Validating paths...");
```

Veja em **Output Panel** do Visual Studio.

### Exception Handling Global

```csharp
// App.xaml.cs
DispatcherUnhandledException += (s, e) => {
    File.AppendAllText(
        Path.Combine(AppContext.BaseDirectory, "crash.log"),
        $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {e.Exception}\n\n");
};
```

---

## 📦 Dependências NuGet

| Pacote | Versão | Propósito |
|--------|--------|----------|
| `CommunityToolkit.Mvvm` | 8.3.2+ | MVVM pattern + RelayCommand |
| `ModernWpfUI` | 0.9.6+ | Componentes design moderno |
| `LiveChartsCore` | 2.0+ | Gráficos em tempo real |
| `LiveChartsCore.SkiaSharpView.WPF` | 2.0+ | Rendering SkiaSharp |

---

## 🚀 Build e Deploy

### Debug

```powershell
cd DhdGui
dotnet build -c Debug
dotnet run -c Debug
```

### Release (Self-contained)

```powershell
dotnet publish -c Release -r win-x64 --self-contained false
# Saída: bin/Release/net8.0-windows/win-x64/publish/
```

### Instalação (Single File)

```powershell
dotnet publish -c Release -r win-x64 -p:PublishSingleFile=true
# Saída: DhdGui.exe (único arquivo)
```

---

## 📝 Convenções de Código

- **Naming:** `PascalCase` para classes e properties públicas
- **XAML:** `x:Name` para elementos com code-behind reference
- **Binding:** `{Binding PropertyName}` sem `Mode=OneWay` (padrão)
- **Async:** Sempre `await` em event handlers
- **Threads:** Nunca atualizar UI diretamente, usar `Dispatcher.InvokeAsync`

---

## 🤝 Contribuindo

1. Mantenha MVVM pattern
2. Sempre adicione unit tests (xUnit)
3. Use `nullable reference types` (`#nullable enable`)
4. Documente ViewModels com XML comments
5. Teste thread-safety com `lock` ou `Interlocked*`

