using System.Net;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;

namespace AuthAPI.InfraRepo;


public class InfraRepoLocalhost : IInfraRepo {

    private readonly HttpClient httpClient;
    private readonly ILogger<InfraRepoLocalhost> _logger;

    public InfraRepoLocalhost(ILogger<InfraRepoLocalhost> logger){
        _logger = logger;
        httpClient = new HttpClient
        {
            BaseAddress = new Uri("http://localhost:5294/")
        };
    }
    public async Task<string> GetuserHash(string email){
        try{
            _logger.LogInformation("GetuserHash attempt: ", httpClient.BaseAddress+ "users/password/" + email);
            var response = await httpClient.GetAsync("users/password/" + email);
            if(response.StatusCode == HttpStatusCode.OK){
                return (await response.Content.ReadAsStringAsync())!;
            }
            else{
                throw new Exception("Error in InfraRepoLocalhost.GetuserHash: " + response.StatusCode);
            }
            //return (await httpClient.GetFromJsonAsync<string>($"users/password/" + email))!;
        }
        catch(Exception e){
            throw new Exception("Error in InfraRepoLocalhost.GetuserHash: " + e.Message);
        }
        
    }


}