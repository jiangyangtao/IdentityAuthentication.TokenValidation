using IdentityAuthentication.Model;
using IdentityAuthentication.Model.Configurations;

namespace IdentityAuthentication.TokenValidation
{
    internal class IdentityAuthenticationConfiguration
    {
        public static AuthenticationEndpoints AuthenticationEndpoints { set; get; }

        public static AuthenticationConfiguration AuthenticationConfiguration { set; get; }

        public static AccessTokenConfiguration AccessTokenConfiguration { set; get; }

        public static RefreshTokenConfiguration RefreshTokenConfiguration { set; get; }

        public static SecretKeyConfigurationBase SecretKeyConfiguration { set; get; }
    }
}
