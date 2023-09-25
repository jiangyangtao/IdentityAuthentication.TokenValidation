using IdentityAuthentication.Model.Enums;
using Microsoft.IdentityModel.Tokens;

namespace IdentityAuthentication.TokenValidation.Abstractions
{
    internal interface ITokenProvider
    {
        TokenType TokenType { get; }

        Task<TokenValidationResult> ValidateTokenAsync(string token);
    }
}
