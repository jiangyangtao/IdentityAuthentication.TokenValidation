using IdentityAuthentication.Model;
using IdentityAuthentication.Model.Configurations;

namespace IdentityAuthentication.TokenValidation
{
    internal class TokenValidationConfiguration
    {
        public static AuthenticationEndpoints AuthenticationEndpoints { set; get; }

        public static AuthenticationConfiguration AuthenticationConfiguration { set; get; }

        public static AccessTokenConfiguration AccessTokenConfiguration { set; get; }

        public static RefreshTokenConfiguration RefreshTokenConfiguration { set; get; }

        public static SecretKeyConfiguration SecretKeyConfiguration { set; get; }

        public static bool HasConfigValue
        {
            get
            {
                return AuthenticationConfiguration != null &&
                        AccessTokenConfiguration != null &&
                        RefreshTokenConfiguration != null &&
                        SecretKeyConfiguration != null;
            }
        }
    }

    internal enum ConnectionType
    {
        Http,

        Grpc,
    }
}
