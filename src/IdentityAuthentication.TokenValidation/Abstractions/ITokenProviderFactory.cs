using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdentityAuthentication.TokenValidation.Abstractions
{
    internal interface ITokenProviderFactory
    {
        public ITokenProvider CreateTokenProvider();
    }
}
