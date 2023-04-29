using AuthServer.Core.Configuration;
using AuthServer.Core.Dtos;
using Microsoft.AspNetCore.Identity;

namespace AuthServer.Core.Services
{
    public interface ITokenService
    {
        TokenDto CreateToken(IdentityUser user);
        ClientTokenDto CreateTokenByClient(Client client);
    }
}
