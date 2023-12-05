using System.Net;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;

namespace AuthAPI.InfraRepo;


public class InfraRepoDocker : IInfraRepo {

    private readonly HttpClient httpClient;
    private readonly ILogger<InfraRepoDocker> _logger;

    public InfraRepoDocker(ILogger<InfraRepoDocker> logger){
        _logger = logger;
        httpClient = new HttpClient
        {
            BaseAddress = new Uri("http://nginx:4000/")
        };
    }
    public async Task<string> GetuserHash(string email){
        try{
            _logger.LogInformation(httpClient.BaseAddress!.ToString() + "users/password/" + email);
            var response = await httpClient.GetAsync("users/password/" + email);
            if(response.StatusCode == HttpStatusCode.OK){
                return (await response.Content.ReadAsStringAsync())!;
            }
            else{
                throw new Exception("Error in InfraRepoLocalhost.GetuserHash: " + response.StatusCode);
            }
        }
        catch(Exception e){
            throw new Exception("Error in InfraRepoDocker.GetuserHash: " + e.Message);
        }
        
    }


}