using AutoMapper;
using Microsoft.Extensions.Logging.Abstractions;

namespace AuthServer.Service.Mapper
{
    public static class ObjectMapper
    {
        private static readonly Lazy<IMapper> lazy = new(() =>
        {
            var loggerFactory = NullLoggerFactory.Instance;
            var config = new MapperConfiguration(cfg =>
            {
                cfg.AddProfile<DtoMapper>();
            }, loggerFactory);

            return config.CreateMapper();
        });

        public static IMapper Mapper => lazy.Value;
    }
}
