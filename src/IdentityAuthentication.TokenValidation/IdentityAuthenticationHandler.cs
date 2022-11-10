using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Text.Encodings.Web;

namespace IdentityAuthentication.TokenValidation
{
    internal class IdentityAuthenticationHandler : AuthenticationHandler<IdentityAuthenticationOptions>
    {
        public IdentityAuthenticationHandler(IOptionsMonitor<IdentityAuthenticationOptions> options, 
            ILoggerFactory logger, 
            UrlEncoder encoder, 
            ISystemClock clock) : base(options, logger, encoder, clock)
        {

        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            throw new NotImplementedException();
        }
    }
}