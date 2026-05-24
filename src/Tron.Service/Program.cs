using Microsoft.Extensions.Hosting.WindowsServices;
using Tron.Alerting.Analyzers;
using Tron.Alerting.Sinks;
using Tron.Core.Config;
using Tron.Core.Interfaces;
using Tron.Monitors;
using Tron.Monitors.Collectors;
using Tron.Monitors.Monitors;
using Tron.Service;

var builder = Host.CreateApplicationBuilder(args);

// Windows Service support — runs as a service OR as a console app
if (OperatingSystem.IsWindows())
    builder.Services.AddWindowsService(opts => opts.ServiceName = "Tron");

// Config
builder.Services.Configure<TronOptions>(builder.Configuration.GetSection(TronOptions.Section));

// Metrics collector
builder.Services.AddSingleton<IMetricsCollector, WindowsMetricsCollector>();

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

// Main worker
builder.Services.AddHostedService<TronWorker>();

var host = builder.Build();
host.Run();

