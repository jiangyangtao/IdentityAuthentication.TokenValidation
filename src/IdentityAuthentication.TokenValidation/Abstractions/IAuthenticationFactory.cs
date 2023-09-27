namespace IdentityAuthentication.TokenValidation.Abstractions
{
    internal interface IAuthenticationFactory
    {
        ITokenValidateProvider CreateTokenValidateProvider();

        ITokenRefreshProvider CreateTokenRefreshProvider();
    }
}
