using AuthServer.Core.Configuration;
using AuthServer.Core.Dtos;
using AuthServer.Core.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using SharedLibrary.Configurations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace AuthServer.Service.Services
{
    public class TokenService : ITokenService
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly CustomTokenOption _customTokenOption;

        public TokenService(UserManager<IdentityUser> userManager, IOptions<CustomTokenOption> options)
        {
            _userManager = userManager;
            _customTokenOption = options.Value;

        }
        private string CreateRefreshToken()
        {
            //return Guid.NewGuid().ToString();
            var numberBytes = new Byte[32];
            using var random = RandomNumberGenerator.Create();
            random.GetBytes(numberBytes);
            return Convert.ToBase64String(numberBytes);
        }
        private IEnumerable<Claim> GetClaims(IdentityUser user,List<String> audiences)
        {
            var userList = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier,user.Id),
                new Claim(JwtRegisteredClaimNames.Email,user.Email),
                new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString())
            };
            userList.AddRange(audiences.Select(x=>new Claim(JwtRegisteredClaimNames.Aud,x)));
            return userList;
        }
        private IEnumerable<Claim> GetClaimsByClient(Client client)
        {
            var claims = new List<Claim>();
            claims.AddRange(client.Audiences.Select(x => new Claim(JwtRegisteredClaimNames.Aud, x)));
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString());
            new Claim(JwtRegisteredClaimNames.Sub, client.Id.ToString());
            return claims;
        }
        public TokenDto CreateToken(IdentityUser user)
        {
            var accessTokenExpiration = DateTime.Now.AddMinutes(_customTokenOption.AccessTokenExpiration);
            var refreshTokenExpiration = DateTime.Now.AddMinutes(_customTokenOption.RefreshTokenExpiration);
            var securityKey = SignService.GetSymmetricSecurityKey(_customTokenOption.SecurityKey);
            SigningCredentials signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature);
            System.IdentityModel.Tokens.Jwt.JwtSecurityToken jwtSecurityToken = new System.IdentityModel.Tokens.Jwt.JwtSecurityToken(
                issuer: _customTokenOption.Issuer,
                expires: accessTokenExpiration,
                notBefore: DateTime.Now,
                claims: GetClaims(user, _customTokenOption.Audience),
                signingCredentials: signingCredentials);
            var handler = new JwtSecurityTokenHandler();
            var token = handler.WriteToken(jwtSecurityToken);
            var tokenDto = new TokenDto
            {
                AccessToken = token,
                RefreshToken = CreateRefreshToken(),
                AccessTokenExpiration = accessTokenExpiration,
                RefreshTokenExpiration = refreshTokenExpiration

            };
            return tokenDto;
        }
        public ClientTokenDto CreateTokenByClient(Client client)
        {
            var accessTokenExpiration = DateTime.Now.AddMinutes(_customTokenOption.AccessTokenExpiration);
            var securityKey = SignService.GetSymmetricSecurityKey(_customTokenOption.SecurityKey);
            SigningCredentials signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature);
            System.IdentityModel.Tokens.Jwt.JwtSecurityToken jwtSecurityToken = new System.IdentityModel.Tokens.Jwt.JwtSecurityToken(
                issuer: _customTokenOption.Issuer,
                expires: accessTokenExpiration,
                notBefore: DateTime.Now,
                claims: GetClaimsByClient(client),
                signingCredentials: signingCredentials);
            var handler = new JwtSecurityTokenHandler();
            var token = handler.WriteToken(jwtSecurityToken);
            var tokenDto = new ClientTokenDto
            {
                AccessToken = token,
                AccessTokenExpiration = accessTokenExpiration,

            };
            return tokenDto;
        }
    }
}
