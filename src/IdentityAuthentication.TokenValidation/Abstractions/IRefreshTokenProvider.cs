using IdentityAuthentication.Model.Configurations;
using IdentityAuthentication.Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace IdentityAuthentication.TokenValidation.Abstractions
{
    internal interface IRefreshTokenProvider
    {
        Task RefreshTokenAsync(IEnumerable<Claim> claims);

        Task RefreshTokenAsync(string expiration);
    }
}
