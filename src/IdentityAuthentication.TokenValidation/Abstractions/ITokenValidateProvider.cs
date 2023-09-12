using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdentityAuthentication.TokenValidation.Abstractions
{
    public interface ITokenValidateProvider
    {
        Task<TokenValidationResult> TokenValidateAsync(string token);
    }
}
