namespace IdentityAuthentication.TokenValidation.Abstractions
{
    internal interface IRemoteFactory
    {
        IServerValidateProvider CreateValidateProvider();
    }
}
