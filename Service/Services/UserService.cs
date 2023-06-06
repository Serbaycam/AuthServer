using AuthServer.Core.Dtos;
using AuthServer.Core.Services;
using AuthServer.Service.Mapper;
using Microsoft.AspNetCore.Identity;
using SharedLibrary.Dtos;

namespace AuthServer.Service.Services
{
    public class UserService : IUserService
    {
        private readonly UserManager<IdentityUser> _userManager;

        public UserService(UserManager<IdentityUser> userManager)
        {
            _userManager = userManager;
        }

        public async Task<Response<UserDto>> CreateUserAsync(CreateUserDto createUserDto)
        {
            var user = new IdentityUser { Email = createUserDto.EMail, UserName = createUserDto.EMail };
            var result = await _userManager.CreateAsync(user, createUserDto.Password);
            if (!result.Succeeded)
            {
                var errors = result.Errors.Select(x => x.Description).ToList();
                return Response<UserDto>.Fail(new ErrorDto(errors, true), 400);
            }
            return Response<UserDto>.Success(ObjectMapper.Mapper.Map<UserDto>(user), 200);
        }

        public async Task<Response<UserDto>> GetUserByEMail(string eMail)
        {
            var user = await _userManager.FindByEmailAsync(eMail);
            if (user == null)
            {
                return Response<UserDto>.Fail("Email not found", 404, true);
            }
            return Response<UserDto>.Success(ObjectMapper.Mapper.Map<UserDto>(user), 200);

        }
    }
}
