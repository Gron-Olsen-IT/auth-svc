namespace AuthAPI.InfraRepo;

using System.Net;
using Microsoft.AspNetCore.Mvc;

public interface IInfraRepo {
    public Task<string> GetuserHash(string userId);
}