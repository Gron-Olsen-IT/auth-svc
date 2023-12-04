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
            var userHash = await _InfraRepo.GetuserHash(email);
            if (userHash == null)
            {
                throw new Exception("User not found");
            }
            else if (password == userHash)
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

    public Task<string> verifyToken(string token)
    {
        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(mySecret);
            tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = true,
                ValidIssuer = myIssuer,
                ValidateAudience = false,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            }, out SecurityToken validatedToken);
            var jwtToken = (JwtSecurityToken)validatedToken;
            var email = jwtToken.Claims.First(x => x.Type == "nameid").Value;
            return Task.FromResult(email);
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


        var token = new JwtSecurityToken(myIssuer, "http://nginx", claims,
        expires: DateTime.Now.AddMinutes(15),
        signingCredentials: credentials);
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

}