using AuthServer.Core.Configuration;
using AuthServer.Core.Dtos;
using AuthServer.Core.Models;
using AuthServer.Core.Repositories;
using AuthServer.Core.Services;
using AuthServer.Core.UnitOfWork;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SharedLibrary.Dtos;

namespace AuthServer.Service.Services
{
    public class AuthenticationService : IAuthenticationService
    {
        private readonly List<Client> _clients;
        private readonly ITokenService _tokenService;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IGenericRepository<UserRefreshToken> _refreshTokenService;
        public AuthenticationService(IOptions<List<Client>> optionsClient,ITokenService tokenService,UserManager<IdentityUser> userManager,IUnitOfWork unitOfWork,IGenericRepository<UserRefreshToken> refreshTokenService)
        {
            _clients = optionsClient.Value;
            _tokenService = tokenService;
            _userManager = userManager;
            _unitOfWork = unitOfWork;
            _refreshTokenService = refreshTokenService;
        }
        public async Task<Response<TokenDto>> CreateToken(SignInDto signInDto)
        {
            if(signInDto == null) throw new ArgumentNullException(nameof(signInDto));
            var user = await _userManager.FindByEmailAsync(signInDto.EMail);
            if (user == null) return Response<TokenDto>.Fail("Email or Password is wrong",400,true);
            if (!await _userManager.CheckPasswordAsync(user, signInDto.Password)) { return Response<TokenDto>.Fail("Email or Password is wrong", 400, true); }
            var token = _tokenService.CreateToken(user);
            var userRefreshToken = await _refreshTokenService.Where(x=>x.UserId == user.Id).SingleOrDefaultAsync();
            if(userRefreshToken==null)
            {
                await _refreshTokenService.AddAsync(new UserRefreshToken { UserId = user.Id, Code = token.RefreshToken, Expiration = token.RefreshTokenExpiration });
            }
            else
            {
                userRefreshToken.Code = token.RefreshToken;
                userRefreshToken.Expiration = token.RefreshTokenExpiration;
            }
            await _unitOfWork.CommitAsync();
            return Response<TokenDto>.Success(token, 200);
        }

        public Task<Response<ClientTokenDto>> CreateTokenByClient(ClientSignInDto clientSignInDto)
        {
            throw new NotImplementedException();
        }

        public Task<Response<TokenDto>> CreateTokenByRefreshToken(string refreshToken)
        {
            throw new NotImplementedException();
        }

        public Task<Response<NoDataDto>> RevokeRefreshToken(string refreshToken)
        {
            throw new NotImplementedException();
        }
    }
}
