using IdentityAuthentication.TokenValidation.Abstractions;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdentityAuthentication.TokenValidation.TokenProviders
{
    internal class TokenProvider : ITokenProvider
    {
        public TokenProvider()
        {
        }

        public bool LocalValidate => throw new NotImplementedException();

        public Task<TokenValidationResult> ValidateTokenAsync(string token)
        {
            throw new NotImplementedException();
        }
    }
}
