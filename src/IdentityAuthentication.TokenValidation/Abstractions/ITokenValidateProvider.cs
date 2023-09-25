using IdentityAuthentication.TokenValidation.Enums;
using Microsoft.IdentityModel.Tokens;

namespace IdentityAuthentication.TokenValidation.Abstractions
{
    internal interface ITokenValidateProvider
    {
        ConnectionType ConnectionType { get; }

        Task<TokenValidationResult> TokenValidateAsync(string token);
    }
}
