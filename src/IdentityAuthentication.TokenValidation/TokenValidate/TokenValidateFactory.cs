using IdentityAuthentication.TokenValidation.Abstractions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdentityAuthentication.TokenValidation.TokenValidate
{
    internal class TokenValidateFactory : ITokenValidateFactory
    {
        public TokenValidateFactory()
        {
        }

        public ITokenValidateProvider CreateTokenValidateProvider()
        {
            throw new NotImplementedException();
        }
    }
}
