using System.Text;
using AuthAPI.InfraRepo;
using AuthAPI.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using NLog;
using NLog.Web;
using OpenTelemetry.Metrics;
using sidecar_lib;

var logger = NLog.LogManager.Setup().LoadConfigurationFromAppSettings().GetCurrentClassLogger();
logger.Debug("init main");

try
{
    var builder = WebApplication.CreateBuilder(args);
    builder.Host.UseNLog();
    // Add services to the container.
    //builder.Services.AddSingleton<IVaultClient>(vaultClient);
    builder.Services.AddScoped<IAuthService, AuthService>();
    builder.Services.AddScoped<IInfraRepo, InfraRepoDocker>();

    //AzureVault azureVault = new AzureVault();
    //string mySecret = await azureVault.GetSecret("Secret");
    //string myIssuer = await azureVault.GetSecret("Issuer");
    string mySecret = "secretSECRET12345678";
    string myIssuer = "issuerISSUER12345678";
    logger.Info("mySecret: " + mySecret);
    logger.Info("myIssuer: " + myIssuer);
    builder
        .Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
        .AddJwtBearer(options =>
        {
            options.TokenValidationParameters = new TokenValidationParameters()
            {
                ValidateIssuer = true,
                ValidIssuer = myIssuer,
                ValidateAudience = true,
                ValidAudience = "http://localhost",
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(mySecret)),
            };
        });

    builder.Services.AddControllers();
    // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
    builder.Services.AddEndpointsApiExplorer();
    builder.Services.ConfigureSwagger("AuthAPI");

    builder
        .Services.AddOpenTelemetry()
        .WithMetrics(builder =>
        {
            builder.AddPrometheusExporter();

            //builder.AddMeter(Instrumentation.MeterName);

            builder.AddMeter("Microsoft.AspNetCore.Hosting", "Microsoft.AspNetCore.Server.Kestrel");

            builder.AddView(
                "http.server.request.duration",
                new ExplicitBucketHistogramConfiguration
                {
                    Boundaries = new double[]
                    {
                        0,
                        0.005,
                        0.01,
                        0.025,
                        0.05,
                        0.075,
                        0.1,
                        0.25,
                        0.5,
                        0.75,
                        1,
                        2.5,
                        5,
                        7.5,
                        10,
                    },
                }
            );
        });

    var app = builder.Build();

    // Configure the HTTP request pipeline.

    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("./v1/swagger.json", "Auth Service API V1");
    });

    app.MapPrometheusScrapingEndpoint();

    app.UseHttpsRedirection();

    app.UseAuthentication();
    app.UseAuthorization();

    app.MapControllers();

    app.Run();
}
catch (Exception ex)
{
    //NLog: catch setup errors
    logger.Error(ex, "Stopped program because of exception");
    throw;
}
finally
{
    // Ensure to flush and stop internal timers/threads before application-exit (Avoid segmentation fault on Linux)
    NLog.LogManager.Flush(TimeSpan.FromSeconds(5));
    NLog.LogManager.Shutdown();
}
