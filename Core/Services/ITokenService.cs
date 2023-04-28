using AuthServer.Core.Configuration;
using AuthServer.Core.Dtos;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthServer.Core.Services
{
    public interface ITokenService
    {
        TokenDto CreateToken(IdentityUser user);
        ClientTokenDto CreateTokenByClient(Client client);
    }
}
