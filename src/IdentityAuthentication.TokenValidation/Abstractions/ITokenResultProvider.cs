using Microsoft.IdentityModel.Tokens;

namespace IdentityAuthentication.TokenValidation.Abstractions
{
    internal interface ITokenResultProvider
    {
        Task<TokenValidationResult> BuildTokenSuccessResultAsync(string json);
    }
}
