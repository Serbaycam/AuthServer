using AuthServer.Core.Dtos;
using FluentValidation;

namespace AuthServer.API.Validations
{
    public class CreateUserDtoValidator : AbstractValidator<CreateUserDto>
    {
        public CreateUserDtoValidator()
        {
            RuleFor(x => x.EMail).NotEmpty().WithMessage("Email is required").EmailAddress().WithMessage("Wrong type please use valid Email type");
            RuleFor(x => x.Password).NotEmpty().WithMessage("Password is required");
        }
    }
}
