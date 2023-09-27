namespace IdentityAuthentication.TokenValidation.Abstractions
{
    internal interface IAuthenticationFactory
    {
        ITokenValidateProvider CreateValidateProvider();

        ITokenRefreshProvider CreateTokenRefreshProvider();
    }
}
