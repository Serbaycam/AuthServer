using AuthServer.Core.Dtos;
using SharedLibrary.Dtos;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthServer.Core.Services
{
    public interface IUserService
    {
        Task<Response<UserDto>> CreateUserAsync(CreateUserDto createUserDto);
        Task<Response<UserDto>> GetUserByEMail(string eMail);
    }
}
