﻿using System.Security.Claims;

namespace IdentityAuthentication.TokenValidation.Abstractions
{
    internal interface IRefreshTokenProvider
    {
        Task RefreshTokenAsync(IEnumerable<Claim> claims);

        Task RefreshTokenAsync(string expiration);
    }
}
