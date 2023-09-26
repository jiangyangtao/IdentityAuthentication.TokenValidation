using Microsoft.IdentityModel.Tokens;

namespace IdentityAuthentication.TokenValidation.Abstractions
{
    internal interface ITokenValidateProvider
    {        
        bool IsRsaValidate { get; }

        Task<TokenValidationResult> TokenValidateAsync(string token);
    }
}
