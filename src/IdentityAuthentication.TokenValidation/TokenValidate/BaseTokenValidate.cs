using Microsoft.IdentityModel.Tokens;

namespace IdentityAuthentication.TokenValidation.TokenValidate
{
    internal abstract class BaseTokenValidate
    {
        protected readonly TokenValidationResult FailTokenResult;

        protected BaseTokenValidate()
        {
            FailTokenResult = new TokenValidationResult { IsValid = false, };
        }
    }
}
