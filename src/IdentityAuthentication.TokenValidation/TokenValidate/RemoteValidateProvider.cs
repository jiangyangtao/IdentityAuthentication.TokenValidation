using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using IdentityAuthentication.TokenValidation.Abstractions;
using Microsoft.IdentityModel.Tokens;

namespace IdentityAuthentication.TokenValidation.TokenValidate
{
    internal class RemoteValidateProvider : ITokenValidateProvider
    {
        public RemoteValidateProvider()
        {
        }

        public bool IsRsaValidate => false;

        public Task<TokenValidationResult> TokenValidateAsync(string token)
        {
            throw new NotImplementedException();
        }
    }
}
