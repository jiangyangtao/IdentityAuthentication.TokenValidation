

namespace IdentityAuthentication.TokenValidation.Abstractions
{
    internal interface ITokenProviderFactory
    {
        public ITokenProvider CreateTokenProvider();
    }
}
