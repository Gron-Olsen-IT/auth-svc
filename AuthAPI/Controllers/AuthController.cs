using Microsoft.AspNetCore.Mvc;
using AuthAPI.InfraRepo;
using AuthAPI.Services;

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

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] Authorization auth)
    {
        try
        {
            return Ok(await _AuthService.ValidateUser(auth.Email!, auth.Password!));
        }
        catch (Exception e)
        {
            return BadRequest(e.Message);
        }
    }
    [HttpPost("verify")]
    public async Task<IActionResult> Verify([FromBody] string token)
    {
        try
        {
            return Ok(await _AuthService.verifyToken(token));
        }
        catch (Exception e)
        {
            return BadRequest(e.Message);
        }
    }
}
