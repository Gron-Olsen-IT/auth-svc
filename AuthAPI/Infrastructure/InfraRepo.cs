using System.Net;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;

namespace AuthAPI.InfraRepo;


public class InfraRepoDocker : IInfraRepo {

    private readonly string INFRA_CONN;
    private readonly HttpClient httpClient;
    private readonly ILogger<InfraRepoDocker> _logger;

    public InfraRepoDocker(ILogger<InfraRepoDocker> logger, IConfiguration configuration){
        _logger = logger;
        try{
            INFRA_CONN = configuration["INFRA_CONN"]!;

        }catch(Exception e){
            throw new Exception("INFRA_CONN not set: " + e.Message);
        }
        
        httpClient = new HttpClient
        {
            BaseAddress = new Uri(INFRA_CONN)
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
                throw new Exception("Error in InfraRepo.GetuserHash: " + response.StatusCode);
            }
        }
        catch(Exception e){
            throw new Exception("Error in InfraRepo.GetuserHash: " + e.Message);
        }
        
    }


}
