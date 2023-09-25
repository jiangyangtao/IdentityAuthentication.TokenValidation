﻿using IdentityAuthentication.Model;
using IdentityAuthentication.Model.Configurations;
using IdentityAuthentication.Model.Models;

namespace IdentityAuthentication.TokenValidation.Abstractions
{
    internal interface IAuthenticationConfigurationProvider
    {
        AuthenticationConfigurationBase AuthenticationConfiguration { get; }

        AccessTokenConfiguration? AccessTokenConfiguration { get; }

        TokenConfigurationBase? RefreshTokenConfiguration { get; }

        RsaVerifySignatureConfiguration? RsaVerifySignatureConfiguration { get; }

        IdentityAuthenticationEndpoints AuthenticationEndpoints { get; }

        bool CanClientValidation { get; }

        void Initialize();

        Task InitializeAsync();
    }
}
