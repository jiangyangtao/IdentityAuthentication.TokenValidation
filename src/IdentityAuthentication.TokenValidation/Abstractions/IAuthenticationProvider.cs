namespace IdentityAuthentication.TokenValidation.Abstractions
{
    internal interface IAuthenticationProvider : ITokenValidateProvider, ITokenRefreshProvider
    {
    }
}
