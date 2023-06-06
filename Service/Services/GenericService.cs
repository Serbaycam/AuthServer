using AuthServer.Core.Repositories;
using AuthServer.Core.Services;
using AuthServer.Core.UnitOfWork;
using AuthServer.Service.Mapper;
using Microsoft.EntityFrameworkCore;
using SharedLibrary.Dtos;
using System.Linq.Expressions;

namespace AuthServer.Service.Services
{
    public class GenericService<TEntity, TDto> : IGenericService<TEntity, TDto> where TEntity : class where TDto : class
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly IGenericRepository<TEntity> _repository;

        public GenericService(IUnitOfWork unitOfWork, IGenericRepository<TEntity> repository)
        {
            _unitOfWork = unitOfWork;
            _repository = repository;
        }

        public async Task<Response<TDto>> AddAsync(TDto tdto)
        {
            var newEntity = ObjectMapper.Mapper.Map<TEntity>(tdto);
            await _repository.AddAsync(newEntity);
            await _unitOfWork.CommitAsync();
            var newDto = ObjectMapper.Mapper.Map<TDto>(newEntity);
            return Response<TDto>.Success(newDto, 200);
        }

        public async Task<Response<IEnumerable<TDto>>> GetAllAsync()
        {
            var entities = ObjectMapper.Mapper.Map<List<TDto>>(await _repository.GetAllAsync());
            return Response<IEnumerable<TDto>>.Success(entities, 200);
        }

        public async Task<Response<TDto>> GetByIdAsync(int id)
        {
            var entity = await _repository.GetByIdAsync(id);
            if (entity == null)
            {
                return Response<TDto>.Fail("Id Not Found", 404, true);
            }
            return Response<TDto>.Success(ObjectMapper.Mapper.Map<TDto>(entity), 200);
        }

        public async Task<Response<NoDataDto>> Remove(int id)
        {
            var isExist = await _repository.GetByIdAsync(id);
            if (isExist == null)
            {
                return Response<NoDataDto>.Fail("Id Not Found", 404, true);
            }
            _repository.Remove(isExist);
            await _unitOfWork.CommitAsync();
            return Response<NoDataDto>.Success(204);
        }

        public async Task<Response<NoDataDto>> Update(TDto tdto, int id)
        {
            var isExistEntity = await _repository.GetByIdAsync(id);
            if (isExistEntity == null)
            {
                return Response<NoDataDto>.Fail("Id Not Found", 404, true);
            }
            var updateEntity = ObjectMapper.Mapper.Map<TEntity>(tdto);
            _repository.Update(updateEntity);
            await _unitOfWork.CommitAsync();
            return Response<NoDataDto>.Success(204);
        }

        public async Task<Response<IEnumerable<TDto>>> Where(Expression<Func<TEntity, bool>> predicate)
        {
            var list = _repository.Where(predicate);
            return Response<IEnumerable<TDto>>.Success(ObjectMapper.Mapper.Map<IEnumerable<TDto>>(await list.ToListAsync()), 200);
        }
    }
}
