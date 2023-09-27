using IdentityAuthentication.Model;
using IdentityAuthentication.Model.Configurations;
using IdentityAuthentication.Model.Models;

namespace IdentityAuthentication.TokenValidation.Abstractions
{
    internal interface IAuthenticationConfigurationProvider
    {
        AuthenticationBaseConfiguration AuthenticationConfiguration { get; }

        AccessTokenConfiguration? AccessTokenConfiguration { get; }

        TokenBaseConfiguration? RefreshTokenConfiguration { get; }

        RsaVerifySignatureConfiguration? RsaVerifySignatureConfiguration { get; }

        IdentityAuthenticationEndpoints AuthenticationEndpoints { get; }

        bool CanClientValidation { get; }

        void Initialize();

        Task InitializeAsync();
    }
}
