using Microsoft.Extensions.Hosting.WindowsServices;
using Tron.Alerting.Sinks;
using Tron.Core.Config;
using Tron.Core.Interfaces;
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

// Monitors
builder.Services.AddSingleton<IMonitor, ResourceMonitor>();
builder.Services.AddSingleton<IMonitor, ServiceMonitor>();
builder.Services.AddSingleton<IMonitor, SecurityEventMonitor>();

// Alert sinks
builder.Services.AddHttpClient<DiscordAlertSink>();
builder.Services.AddSingleton<IAlertSink, DiscordAlertSink>();

// Main worker
builder.Services.AddHostedService<TronWorker>();

var host = builder.Build();
host.Run();

