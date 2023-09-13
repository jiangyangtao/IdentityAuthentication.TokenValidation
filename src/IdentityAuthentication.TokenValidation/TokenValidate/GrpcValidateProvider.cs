using IdentityAuthentication.TokenValidation.Abstractions;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdentityAuthentication.TokenValidation.TokenValidate
{
    internal class GrpcValidateProvider : BaseTokenValidate, ITokenValidateProvider
    {
        public GrpcValidateProvider()
        {
        }

        public Task<TokenValidationResult> TokenValidateAsync(string token)
        {
            throw new NotImplementedException();
        }
    }
}
