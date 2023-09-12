
namespace IdentityAuthentication.TokenValidation.Abstractions
{
    internal interface ITokenValidateFactory
    {
        ITokenValidateProvider CreateTokenValidateProvider();
    }
}
