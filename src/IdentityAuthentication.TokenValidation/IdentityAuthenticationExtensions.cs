using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;

namespace IdentityAuthentication.TokenValidation
{
    public static class IdentityAuthenticationExtensions
    {
        /// <summary>
        /// Registers the Identity authentication handler.
        /// </summary>
        /// <param name="builder">The builder.</param>
        /// <returns></returns>
        public static AuthenticationBuilder AddIdentityAuthentication(this AuthenticationBuilder builder)
            => builder.AddIdentityAuthentication(IdentityAuthenticationDefaults.AuthenticationScheme);

        /// <summary>
        /// Registers the Identity authentication handler.
        /// </summary>
        /// <param name="builder">The builder.</param>
        /// <param name="authenticationScheme">The authentication scheme.</param>
        /// <returns></returns>
        public static AuthenticationBuilder AddIdentityAuthentication(this AuthenticationBuilder builder, string authenticationScheme)
            => builder.AddIdentityAuthentication(authenticationScheme, configureOptions: null);

        /// <summary>
        /// Registers the Identity authentication handler.
        /// </summary>
        /// <param name="builder">The builder.</param>
        /// <param name="configureOptions">The configure options.</param>
        /// <returns></returns>
        public static AuthenticationBuilder AddIdentityAuthentication(this AuthenticationBuilder builder, Action<IdentityAuthenticationOptions> configureOptions) =>
            builder.AddIdentityAuthentication(IdentityAuthenticationDefaults.AuthenticationScheme, configureOptions);

        /// <summary>
        /// Registers the Identity authentication handler.
        /// </summary>
        /// <param name="builder">The builder.</param>
        /// <param name="authenticationScheme">The authentication scheme.</param>
        /// <param name="configureOptions">The configure options.</param>
        /// <returns></returns>
        public static AuthenticationBuilder AddIdentityAuthentication(this AuthenticationBuilder builder, string authenticationScheme, Action<IdentityAuthenticationOptions> configureOptions)
        {
            builder.AddJwtBearer(authenticationScheme + IdentityAuthenticationDefaults.JwtAuthenticationScheme, configureOptions: null);

            return builder.AddScheme<IdentityAuthenticationOptions, IdentityAuthenticationHandler>(authenticationScheme, configureOptions);
        }
    }
}
