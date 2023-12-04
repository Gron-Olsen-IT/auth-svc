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

var logger = NLog.LogManager.Setup().LoadConfigurationFromAppSettings().GetCurrentClassLogger();
logger.Debug("init main");


try
{

    //var EndPoint = "https://vaultservice:8201/";
    var EndPoint = Environment.GetEnvironmentVariable("VAULT_ADDR");
    logger.Info("Vault address: " + EndPoint);
    if (EndPoint == null)
    {
        throw new Exception("Environment variable VAULT_ADDR not set");
    }
    var httpClientHandler = new HttpClientHandler
    {
        ServerCertificateCustomValidationCallback = (message, cert, chain, sslPolicyErrors) => { return true; }
    };

    // Initialize one of the several auth methods.
    IAuthMethodInfo authMethod = new TokenAuthMethodInfo("00000000-0000-0000-0000-000000000000");
    // Initialize settings. You can also set proxies, custom delegates etc. here.
    var vaultClientSettings = new VaultClientSettings(EndPoint, authMethod)
    {
        Namespace = "",
        MyHttpClientProviderFunc = handler
        => new HttpClient(httpClientHandler)
        {
            BaseAddress = new Uri(EndPoint)
        }
    };
    // Initialize client with settings.
    IVaultClient vaultClient = new VaultClient(vaultClientSettings);
    // Use client to read a key-value secret.
    logger.Info("Reading secret" + vaultClientSettings.ToString());
    Secret<SecretData> kv2Secret = await vaultClient.V1.Secrets.KeyValue.V2.ReadSecretAsync(path: "authentication", mountPoint: "secret");
    string mySecret = kv2Secret.Data.Data["Secret"].ToString()!;
    string myIssuer = kv2Secret.Data.Data["Issuer"].ToString()!;
    logger.Info("mySecret: " + mySecret);
    logger.Info("myIssuer: " + myIssuer);




    var builder = WebApplication.CreateBuilder(args);
    // Add services to the container.
    builder.Services.AddSingleton<IVaultClient>(vaultClient);
    builder.Services.AddScoped<IAuthService, AuthService>();
    builder.Services.AddScoped<IInfraRepo, InfraRepoDocker>();

    builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters()
        {
            ValidateIssuer = true,
            ValidIssuer = myIssuer,
            ValidateAudience = true,
            ValidAudience = "http://127.0.0.1",

            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(mySecret))
        };
    });

    builder.Services.AddControllers();
    // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
    builder.Services.AddEndpointsApiExplorer();
    builder.Services.AddSwaggerGen();

    var app = builder.Build();

    // Configure the HTTP request pipeline.
    if (app.Environment.IsDevelopment())
    {
        app.UseSwagger();
        app.UseSwaggerUI();
    }


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