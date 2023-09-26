using IdentityAuthentication.Model.Enums;
using Microsoft.IdentityModel.Tokens;
using System.ComponentModel.DataAnnotations;

namespace IdentityAuthentication.TokenValidation.Abstractions
{
    internal interface ITokenProvider
    {
        Task<TokenValidationResult> ValidateTokenAsync(string token);
    }
}
