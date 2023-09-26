namespace IdentityAuthentication.TokenValidation.Abstractions
{
    internal interface IRemoteValidateFactory
    {
        IServerValidateProvider CreateValidateProvider();
    }
}
