﻿using IdentityAuthentication.Model.Extensions;
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
        private readonly IAuthenticationConfigurationProvider _configurationProvider;
        private readonly AuthenticateResult EmptyAuthenticateSuccessResult;

        public IdentityAuthenticationHandler(IOptionsMonitor<IdentityAuthenticationOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock,
            ITokenProvider tokenProvider,
            IAuthenticationConfigurationProvider configurationProvider) : base(options, logger, encoder, clock)
        {
            _tokenProvider = tokenProvider;
            _configurationProvider = configurationProvider;

            var ticket = new AuthenticationTicket(new ClaimsPrincipal(), IdentityAuthenticationDefaultKeys.AuthenticationScheme);
            EmptyAuthenticateSuccessResult = AuthenticateResult.Success(ticket);
        }

        protected new IdentityAuthenticationEvents Events
        {
            get
            {
                if (base.Events == null) return null;

                return base.Events! as IdentityAuthenticationEvents;
            }
            set => base.Events = value;
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var endpoint = Context.GetEndpoint();
            if (endpoint == null) return AuthenticateResult.NoResult();

            var messageReceivedContext = new MessageReceivedContext(Context, Scheme, Options);
            if (Events != null && Events.MessageReceived != null) await Events.MessageReceived(messageReceivedContext);

            if (messageReceivedContext.Result != null)
            {
                return messageReceivedContext.Result;
            }

            var allowAnonymous = endpoint.Metadata.GetMetadata<IAllowAnonymous>();
            if (allowAnonymous != null) return EmptyAuthenticateSuccessResult;

            await _configurationProvider.InitializeAsync();

            var token = messageReceivedContext.Token;
            if (token.IsNullOrEmpty())
            {
                token = Request.Headers.GetAuthorization();
                if (token.IsNullOrEmpty()) return AuthenticateResult.NoResult();
            }
            else
            {
                // 如果是 SignalR，则将 token 放到 header
                Context.Request.Headers.SetAuthorization(token);
            }

            var tokenValidationResult = await _tokenProvider.ValidateTokenAsync(token);
            if (tokenValidationResult.IsValid == false) return AuthenticateResult.NoResult();


            var principal = new ClaimsPrincipal(tokenValidationResult.ClaimsIdentity);
            var tokenValidatedContext = new TokenValidatedContext(Context, Scheme, Options)
            {
                Principal = principal,
                SecurityToken = tokenValidationResult.SecurityToken
            };

            if (Events != null && Events.OnTokenValidated != null) await Events.OnTokenValidated(tokenValidatedContext);
            if (tokenValidatedContext.Result != null) return tokenValidatedContext.Result;

            tokenValidatedContext.Success();
            return tokenValidatedContext.Result!;
        }
    }
}