using System.Net;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;

namespace AuthAPI.InfraRepo;


public class InfraRepoDocker : IInfraRepo {

    private readonly HttpClient httpClient;

    public InfraRepoDocker(){
        httpClient = new HttpClient
        {
            BaseAddress = new Uri("http://nginx:4000/")
        };
    }
    public async Task<string> GetuserHash(string email){
        try{
            return (await httpClient.GetFromJsonAsync<string>($"users/password/" + email))!;
        }
        catch(Exception e){
            throw new Exception("Error in InfraRepoRender.GetuserHash: " + e.Message);
        }
        
    }


}