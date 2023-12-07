using Microsoft.IdentityModel.JsonWebTokens;

namespace AuthAPI.Services
{
    public interface IAuthService
    {
        public Task<string> ValidateUser(string email, string password);
        public Task<string> GenerateJwtToken(string email);
        public Task<string> ValidateToken(string token);
    }
}