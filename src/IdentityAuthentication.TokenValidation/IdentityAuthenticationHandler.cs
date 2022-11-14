using IdentityAuthentication.Model.Handlers;
using IdentityAuthentication.Model.Handles;
using IdentityAuthentication.TokenValidation.Abstractions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Text.Encodings.Web;

namespace IdentityAuthentication.TokenValidation
{
    internal class IdentityAuthenticationHandler : AuthenticationHandler<IdentityAuthenticationOptions>
    {
        private readonly ITokenProvider _tokenProvider;

        private readonly AuthenticateResult EmptyAuthenticateSuccessResult;

        public IdentityAuthenticationHandler(IOptionsMonitor<IdentityAuthenticationOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock,
            ITokenProviderFactory tokenProviderFactory) : base(options, logger, encoder, clock)
        {
            _tokenProvider = tokenProviderFactory.CreateTokenProvider();


            var ticket = new AuthenticationTicket(new ClaimsPrincipal(), IdentityAuthenticationDefaults.AuthenticationScheme);
            EmptyAuthenticateSuccessResult = AuthenticateResult.Success(ticket);
        }

        protected new IdentityAuthenticationEvents Events
        {
            get => (IdentityAuthenticationEvents)base.Events!;
            set => base.Events = value;
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var messageReceivedContext = new MessageReceivedContext(Context, Scheme, Options);

            await Events.MessageReceived(messageReceivedContext);
            if (messageReceivedContext.Result != null)
            {
                return messageReceivedContext.Result;
            }

            var allowAnonymous = Context.GetEndpoint().Metadata.GetMetadata<IAllowAnonymous>();
            if (allowAnonymous != null) return EmptyAuthenticateSuccessResult;

            var token = messageReceivedContext.Token;
            if (string.IsNullOrEmpty(token))
            {
                token = Request.Headers.Authorization.ToString();
                if (token.IsNullOrEmpty()) return AuthenticateResult.NoResult();

                if (token.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                {
                    token = token["Bearer ".Length..].Trim();
                }

                if (string.IsNullOrEmpty(token)) return AuthenticateResult.NoResult();
            }
            else
            {
                // 如果是 SignalR，则将 token 放到 header
                Context.Request.Headers.Add("Authorization", token);
            }

            var tokenValidationResult = await _tokenProvider.ValidateTokenAsync(token);
            if (tokenValidationResult.IsValid == false) return AuthenticateResult.NoResult();


            var principal = new ClaimsPrincipal(tokenValidationResult.ClaimsIdentity);
            var tokenValidatedContext = new TokenValidatedContext(Context, Scheme, Options)
            {
                Principal = principal,
                SecurityToken = tokenValidationResult.SecurityToken
            };

            await Events.OnTokenValidated(tokenValidatedContext);
            if (tokenValidatedContext.Result != null) return tokenValidatedContext.Result;

            tokenValidatedContext.Success();
            return tokenValidatedContext.Result!;
        }
    }
}