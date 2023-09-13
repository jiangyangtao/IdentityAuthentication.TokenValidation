﻿using IdentityAuthentication.TokenValidation.Abstractions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdentityAuthentication.TokenValidation.TokenRefresh
{
    internal class HttpRefreshProvider : ITokenRefreshProvider
    {
        public HttpRefreshProvider()
        {
        }

        public ConnectionType ConnectionType => ConnectionType.Http;
    }
}
