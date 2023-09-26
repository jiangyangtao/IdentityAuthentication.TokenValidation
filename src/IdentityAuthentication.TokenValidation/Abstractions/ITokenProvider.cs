using Microsoft.IdentityModel.Tokens;

namespace IdentityAuthentication.TokenValidation.Abstractions
{
    internal interface ITokenProvider
    {
        Task<TokenValidationResult> ValidateTokenAsync(string token);
    }
}
