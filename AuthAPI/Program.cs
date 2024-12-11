using AuthAPI.Services;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using VaultSharp;
using VaultSharp.V1.AuthMethods.Token;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.Commons;
using AuthAPI.InfraRepo;
using NLog;
using NLog.Web;
using sidecar_lib;
using OpenTelemetry.Resources;
using OpenTelemetry.Metrics;


var logger = NLog.LogManager.Setup().LoadConfigurationFromAppSettings().GetCurrentClassLogger();
logger.Debug("init main");


try
{
    var builder = WebApplication.CreateBuilder(args);
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
    builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
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
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(mySecret))
        };
    });


    builder.Services.AddControllers();
    // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
    builder.Services.AddEndpointsApiExplorer();
    builder.Services.ConfigureSwagger("AuthAPI");

    builder.Services.AddOpenTelemetry()
    .WithMetrics(builder =>
    {
        builder.AddPrometheusExporter();
        
        //builder.AddMeter(Instrumentation.MeterName);

        builder.AddMeter("Microsoft.AspNetCore.Hosting","Microsoft.AspNetCore.Server.Kestrel");
        
        builder.AddView("http.server.request.duration",
            new ExplicitBucketHistogramConfiguration
            {
                Boundaries = new double[] { 0, 0.005, 0.01, 0.025, 0.05,
                       0.075, 0.1, 0.25, 0.5, 0.75, 1, 2.5, 5, 7.5, 10 }
            });       

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
    NLog.LogManager.Shutdown();
}

