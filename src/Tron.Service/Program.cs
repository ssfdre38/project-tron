using Tron.Alerting.Analyzers;
using Tron.Alerting.Sinks;
using Tron.Core.Config;
using Tron.Core.Interfaces;
using Tron.Monitors;
using Tron.Monitors.Collectors;
using Tron.Monitors.Monitors;
using Tron.Service;

var builder = Host.CreateApplicationBuilder(args);

// Windows Service support — runs as a service OR as a console app on Windows
#if TRON_WINDOWS
builder.Services.AddWindowsService(opts => opts.ServiceName = "Tron");
#else
// Linux: integrate with systemd (notify-ready, watchdog, journal logging)
builder.Services.AddSystemd();
#endif

// Config
builder.Services.Configure<TronOptions>(builder.Configuration.GetSection(TronOptions.Section));

// Metrics collector — platform-selected at compile time
#if TRON_WINDOWS
builder.Services.AddSingleton<IMetricsCollector, WindowsMetricsCollector>();
#else
builder.Services.AddSingleton<IMetricsCollector, UnixMetricsCollector>();
#endif

// Baseline persistence
builder.Services.AddSingleton<IBaselineRepository, JsonBaselineRepository>();

// Monitors — order matters for readability in alerts
builder.Services.AddSingleton<IMonitor, ResourceMonitor>();
builder.Services.AddSingleton<IMonitor, ServiceMonitor>();
builder.Services.AddSingleton<IMonitor, ProcessMonitor>();
builder.Services.AddSingleton<IMonitor, NetworkConnectionMonitor>();
builder.Services.AddSingleton<IMonitor, SecurityEventMonitor>();
builder.Services.AddSingleton<IMonitor, BaselineMonitor>();

// Alert sinks
builder.Services.AddHttpClient<DiscordAlertSink>();
builder.Services.AddSingleton<IAlertSink, DiscordAlertSink>();

// AI analyzer (local model endpoint)
builder.Services.AddHttpClient<LocalModelAnalyzer>();
builder.Services.AddSingleton<IAiAnalyzer, LocalModelAnalyzer>();

// State service (shared between TronWorker and DashboardService)
builder.Services.AddSingleton<TronStateService>();

// Main worker
builder.Services.AddHostedService<TronWorker>();

// Embedded web dashboard
builder.Services.AddHostedService<DashboardService>();

var host = builder.Build();
host.Run();

