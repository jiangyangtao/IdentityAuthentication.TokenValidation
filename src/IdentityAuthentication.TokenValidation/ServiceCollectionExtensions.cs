using IdentityAuthentication.Model.Handles;
using IdentityAuthentication.TokenValidation.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace IdentityAuthentication.TokenValidation
{
    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddAuthentication(this IServiceCollection services, Action<IdentityAuthenticationOptions> configureOptions)
        {
            var config = new IdentityAuthenticationOptions();
            configureOptions(config);
            IdentityAuthenticationOptions.AuthorityUrl = config.GetAuthorityUri();

            services.AddAuthentication(options =>
            {
                options.DefaultScheme = IdentityAuthenticationDefaults.AuthenticationScheme;
                options.DefaultAuthenticateScheme = IdentityAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = IdentityAuthenticationDefaults.AuthenticationScheme;
                options.DefaultForbidScheme = IdentityAuthenticationDefaults.AuthenticationScheme;
                options.DefaultSignInScheme = IdentityAuthenticationDefaults.AuthenticationScheme;
                options.DefaultSignOutScheme = IdentityAuthenticationDefaults.AuthenticationScheme;
            }).AddScheme<IdentityAuthenticationOptions, IdentityAuthenticationHandler>(IdentityAuthenticationDefaults.AuthenticationScheme, options =>
            {
                options.Events = config.Events;
                options.Authority = config.Authority;
            });

            services.AddSingleton<ConfigurationService>();
            services.AddSingleton<AuthenticationEndpointService>();
            return services;
        }

        public static IApplicationBuilder UseIdentityAuthentication(this IApplicationBuilder builder)
        {
            var serviceScope = builder.ApplicationServices.GetRequiredService<IServiceScopeFactory>().CreateScope();
            var configurationService = serviceScope.ServiceProvider.GetRequiredService<ConfigurationService>();

            configurationService.InitializationConfiguration();
            return builder;
        }
    }
}
