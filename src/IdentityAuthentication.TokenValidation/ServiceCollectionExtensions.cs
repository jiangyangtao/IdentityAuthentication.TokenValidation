using Grpc.Core;
using Grpc.Net.Client.Configuration;
using IdentityAuthentication.Application.Grpc.Provider;
using IdentityAuthentication.Model.Extensions;
using IdentityAuthentication.Model.Handlers;
using IdentityAuthentication.Model.Handles;
using IdentityAuthentication.TokenValidation.Abstractions;
using IdentityAuthentication.TokenValidation.TokenProviders;
using IdentityAuthentication.TokenValidation.TokenRefresh;
using IdentityAuthentication.TokenValidation.TokenValidate;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace IdentityAuthentication.TokenValidation
{
    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddIdentityAuthentication(this IServiceCollection services) => AddAuthentication(services);

        public static IServiceCollection AddIdentityAuthentication(this IServiceCollection services, IdentityAuthenticationEvents authenticationEvents)
            => AddAuthentication(services, authenticationEvents);

        public static IServiceCollection AddAuthentication(this IServiceCollection services)
        {
            var endpoing = services.GetEndpoint();
            return AddAuthentication(services, endpoing);
        }

        public static IServiceCollection AddAuthentication(this IServiceCollection services, IdentityAuthenticationEvents authenticationEvents)
        {
            var endpoing = services.GetEndpoint();
            return AddAuthentication(services, endpoing, authenticationEvents);
        }

        public static IServiceCollection AddAuthentication(this IServiceCollection services, string authenticationEndpoint)
        {
            if (authenticationEndpoint.IsNullOrEmpty()) throw new ArgumentNullException(nameof(authenticationEndpoint));

            return AddAuthentication(services, options =>
            {
                options.Authority = authenticationEndpoint;
            });
        }

        public static IServiceCollection AddAuthentication(this IServiceCollection services, string authenticationEndpoint, IdentityAuthenticationEvents authenticationEvents)
        {
            if (authenticationEndpoint.IsNullOrEmpty()) throw new ArgumentNullException(nameof(authenticationEndpoint));

            return AddAuthentication(services, options =>
            {
                options.Authority = authenticationEndpoint;

                if (authenticationEvents != null) options.Events = authenticationEvents;
            });
        }

        public static IServiceCollection AddAuthentication(this IServiceCollection services, Action<IdentityAuthenticationOptions> optionsAction)
        {
            var authenticationOptions = new IdentityAuthenticationOptions();
            optionsAction(authenticationOptions);

            var authorityUrl = authenticationOptions.GetAuthorityUri();
            services.Configure<TokenValidationOptions>(options =>
            {
                options.AuthorityUrl = authorityUrl;
                options.EnableJWTRefreshToken = authenticationOptions.EnableJWTRefreshToken;
            });
            services.AddAuthentication(options =>
            {
                options.DefaultScheme = IdentityAuthenticationDefaultKeys.AuthenticationScheme;
                options.DefaultAuthenticateScheme = IdentityAuthenticationDefaultKeys.AuthenticationScheme;
                options.DefaultChallengeScheme = IdentityAuthenticationDefaultKeys.AuthenticationScheme;
                options.DefaultForbidScheme = IdentityAuthenticationDefaultKeys.AuthenticationScheme;
                options.DefaultSignInScheme = IdentityAuthenticationDefaultKeys.AuthenticationScheme;
                options.DefaultSignOutScheme = IdentityAuthenticationDefaultKeys.AuthenticationScheme;
            }).AddScheme<IdentityAuthenticationOptions, IdentityAuthenticationHandler>(IdentityAuthenticationDefaultKeys.AuthenticationScheme, options =>
            {
                options.Events = authenticationOptions.Events;
                options.Authority = authenticationOptions.Authority;
            });

            services.AddScoped<ITokenProvider, TokenProvider>();

            services.AddScoped<ITokenValidateFactory, TokenValidateFactory>();
            services.AddScoped<ITokenValidateProvider, HttpAuthenticationProvider>();
            services.AddScoped<ITokenValidateProvider, GrpcAuthenticationProvider>();

            services.AddScoped<IRefreshTokenProvider, RefreshTokenProvider>();
            services.AddScoped<ITokenRefreshFactory, TokenRefreshFactory>();
            services.AddScoped<ITokenRefreshProvider, HttpRefreshProvider>();
            services.AddScoped<ITokenRefreshProvider, GrpcRefreshProvider>();

            services.AddScoped<IGrpcProvider, GrpcProvider>();
            services.AddSingleton<IAuthenticationConfigurationProvider, AuthenticationConfigurationProvider>();

            services.AddGrpcClient<TokenGrpcProvider.TokenGrpcProviderClient>(options =>
            {
                options.Address = authorityUrl;
                options.ChannelOptionsActions.Add((channelOptions) =>
                {
                    // 允许自签名证书
                    channelOptions.HttpHandler = new HttpClientHandler
                    {
                        ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
                    };

                    var serviceConfig = new ServiceConfig();
                    serviceConfig.MethodConfigs.Add(new MethodConfig
                    {
                        Names = { MethodName.Default },
                        RetryPolicy = new RetryPolicy       // 重试策略
                        {
                            MaxAttempts = 5,
                            InitialBackoff = TimeSpan.FromSeconds(1),
                            MaxBackoff = TimeSpan.FromSeconds(5),
                            BackoffMultiplier = 1.5,
                            RetryableStatusCodes = { StatusCode.Unavailable }
                        }
                    });
                    channelOptions.ServiceConfig = serviceConfig;
                });
            });

            services.AddHttpClient(Options.DefaultName).ConfigurePrimaryHttpMessageHandler(() =>
            {
                return new HttpClientHandler
                {
                    ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator,
                    CheckCertificateRevocationList = false,
                };
            });
            services.AddHttpContextAccessor();

            return services;
        }

        public static IApplicationBuilder UseIdentityAuthentication(this IApplicationBuilder builder)
        {
            var serviceScope = builder.ApplicationServices.GetRequiredService<IServiceScopeFactory>().CreateScope();
            var configurationProvider = serviceScope.ServiceProvider.GetRequiredService<IAuthenticationConfigurationProvider>();

            configurationProvider.Initialize();
            return builder;
        }

        private static string GetEndpoint(this IServiceCollection services)
        {
            var serviceProvider = services.BuildServiceProvider();
            var configuration = serviceProvider.GetRequiredService<IConfiguration>();
            var authenticationConfig = configuration.GetSection("Authentication") ?? throw new KeyNotFoundException("In configuration not found Authentication");
            var endpoint = authenticationConfig.GetValue<string>("Endpoint");

            return endpoint ?? throw new KeyNotFoundException("In configuration not found Endpoint of Authentication");
        }
    }
}
