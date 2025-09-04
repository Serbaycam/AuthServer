using AuthServer.Core.Configuration;
using AuthServer.Core.Dtos;
using Microsoft.AspNetCore.Identity;
using System.Threading.Tasks;

namespace AuthServer.Core.Services
{
    public interface ITokenService
    {
        Task<TokenDto> CreateTokenAsync(IdentityUser user);
        ClientTokenDto CreateTokenByClient(Client client);
    }
}
