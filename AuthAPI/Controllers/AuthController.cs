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
            return Unauthorized("Login credentials not found");
        }
    }
    [AllowAnonymous]
    [HttpPost("authorize")]
    public async Task<IActionResult> Authorize()
    {
        try
        {
            string JWT_TOKEN = Request.Headers["Authorization"]!.ToString()!.Replace("Bearer ", string.Empty);
            _logger.LogInformation("Authorize attempt: " + JWT_TOKEN);
            return Ok(await _AuthService.ValidateToken(JWT_TOKEN));
        }
        catch (Exception e)
        {
            _logger.LogError(e.Message);
            return BadRequest(e.Message);
        }
    }

    [Authorize]
    [HttpGet("test")]
    public IActionResult Test()
    {
        try
        {
            _logger.LogInformation("Test attempt");
            return Ok("Test successful");
        }
        catch (Exception e)
        {
            _logger.LogError(e.Message);
            return BadRequest(e.Message);
        }
    }
}
