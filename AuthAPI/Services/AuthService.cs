namespace AuthAPI.Services;
using AuthAPI.InfraRepo;

using Microsoft.AspNetCore.Mvc;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authorization;
using VaultSharp;
using VaultSharp.V1.Commons;
using System.Net.Http.Headers;
using System.Security.Cryptography;

public class AuthService : IAuthService
{
    private readonly ILogger<AuthService> _logger;
    private readonly IInfraRepo _InfraRepo;
    private readonly IVaultClient _vaultClient;
    private string? mySecret;
    private string? myIssuer;

    public AuthService(ILogger<AuthService> logger, IInfraRepo InfraRepo, IVaultClient vaultClient)
    {
        _logger = logger;
        _InfraRepo = InfraRepo;
        _vaultClient = vaultClient;
    }


    public async Task<string> ValidateUser(string email, string password)
    {
        try
        {
            _logger.LogInformation("ValidateUser attempt at " + DateTime.Now + " with email: " + email + " and password: " + password);
            var userPasswordDatabase = await _InfraRepo.GetuserHash(email);
            _logger.LogInformation("Password in database: " + userPasswordDatabase);
            string Sha1Password = Sha1(password);
            _logger.LogInformation("Hased password from body: " + Sha1Password);
            if (userPasswordDatabase == null)
            {
                throw new Exception("User not found");
            }
            else if (userPasswordDatabase == Sha1Password)
            {
                return await GenerateJwtToken(email);
            }
            else
            {
                throw new Exception("Wrong password");
            }
        }
        catch (Exception e)
        {
            throw new Exception("Error in AuthService.ValidateUser: " + e.Message);
        }

    }

    public async Task<string> ValidateToken(string token)
    {
        _logger.LogInformation("verifyToken attempt at " + DateTime.Now);
        Secret<SecretData> kv2Secret = await _vaultClient.V1.Secrets.KeyValue.V2.ReadSecretAsync(path: "authentication", mountPoint: "secret");
        mySecret = kv2Secret.Data.Data["Secret"].ToString()!;
        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(mySecret);
            try
            {
                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ClockSkew = TimeSpan.Zero
                }, out SecurityToken validatedToken);
                var jwtToken = (JwtSecurityToken)validatedToken;
                var accountId = jwtToken.Claims.First(x => x.Type == ClaimTypes.NameIdentifier).Value;
                return accountId;
            }
            catch (Exception e)
            {
                throw new Exception("Error in AuthService.verifyToken: " + e.Message);
            }
        }
        catch (Exception e)
        {
            throw new Exception("Error in AuthService.verifyToken: " + e.Message);
        }
    }
    
    public async Task<string> GenerateJwtToken(string email)
    {
        Secret<SecretData> kv2Secret = await _vaultClient.V1.Secrets.KeyValue.V2.ReadSecretAsync(path: "authentication", mountPoint: "secret");
        mySecret = kv2Secret.Data.Data["Secret"].ToString()!;
        myIssuer = kv2Secret.Data.Data["Issuer"].ToString()!;

        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(mySecret));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
        var claims = new[] { new Claim(ClaimTypes.NameIdentifier, email) };

        _logger.LogInformation($"Token generated at: {DateTime.Now}");

        var token = new JwtSecurityToken(myIssuer, "http://localhost", claims,
        expires: DateTime.Now.AddMinutes(60),
        signingCredentials: credentials);
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public static string Sha1(string input)
    {
        using var sha1 = SHA1.Create();
        var hash = sha1.ComputeHash(Encoding.UTF8.GetBytes(input));
        var sb = new StringBuilder(hash.Length * 2);

        foreach (byte b in hash)
        {
            sb.Append(b.ToString("x2"));
        }
        return sb.ToString().ToUpper();
    }


}