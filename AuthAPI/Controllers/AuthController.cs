using Microsoft.AspNetCore.Mvc;
using AuthAPI.InfraRepo;
using AuthAPI.Services;
using Microsoft.AspNetCore.Authorization;

namespace AuthAPI.Controllers;

[ApiController]
[Route("[controller]")]
public class AuthController : ControllerBase
{
    private readonly ILogger<AuthController> _logger;
    
    private readonly IAuthService _AuthService;

    public AuthController(ILogger<AuthController> logger, IAuthService IAuthService)
    {
        _logger = logger;
        _AuthService = IAuthService;
    }

    [AllowAnonymous]
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] Authorization auth)
    {
        try
        {   
            _logger.LogInformation("Login attempt");
            return Ok(await _AuthService.ValidateUser(auth.Email!, auth.Password!));
        }
        catch (Exception e)
        {
            _logger.LogError(e.Message);
            return BadRequest(e.Message);
        }
    }
    [AllowAnonymous]
    [HttpPost("verify")]
    public async Task<IActionResult> Verify([FromBody] string token)
    {
        try
        {
            _logger.LogInformation("Verify attempt");
            return Ok(await _AuthService.verifyToken(token));
        }
        catch (Exception e)
        {
            _logger.LogError(e.Message);
            return BadRequest(e.Message);
        }
    }
}
