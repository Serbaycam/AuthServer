using AuthServer.Core.Dtos;
using AuthServer.Core.Models;
using AutoMapper;
using Microsoft.AspNetCore.Identity;

namespace AuthServer.Service.Mapper
{
    internal class DtoMapper : Profile
    {
        public DtoMapper()
        {
            CreateMap<ProductDto, Product>().ReverseMap();
            CreateMap<UserDto, IdentityUser>().ReverseMap();
        }
    }
}
