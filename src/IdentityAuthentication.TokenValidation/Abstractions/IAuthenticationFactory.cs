namespace IdentityAuthentication.TokenValidation.Abstractions
{
    internal interface IAuthenticationFactory
    {
        IServerValidateProvider CreateValidateProvider();
    }
}
