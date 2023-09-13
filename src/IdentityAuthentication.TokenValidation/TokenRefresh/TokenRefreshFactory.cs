using IdentityAuthentication.TokenValidation.Abstractions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdentityAuthentication.TokenValidation.TokenRefresh
{
    internal class TokenRefreshFactory : ITokenRefreshFactory
    {
        private readonly IServiceProvider _serviceProvider;

        public TokenRefreshFactory(IServiceProvider serviceProvider)
        {
            _serviceProvider = serviceProvider;
        }

        public ITokenRefreshProvider CreateTokenRefreshProvider()
        {

        }
    }
}
