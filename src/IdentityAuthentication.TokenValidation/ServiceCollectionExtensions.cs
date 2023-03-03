using Grpc.Core;
using Grpc.Net.Client.Configuration;
using IdentityAuthentication.Application.Grpc.Provider;
using IdentityAuthentication.Model.Handles;
using IdentityAuthentication.TokenValidation.Abstractions;
using IdentityAuthentication.TokenValidation.Providers;
using IdentityAuthentication.TokenValidation.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace IdentityAuthentication.TokenValidation
{
    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddAuthentication(this IServiceCollection services, Action<IdentityAuthenticationOptions> action)
        {
            var authenticationOptions = new IdentityAuthenticationOptions();
            action(authenticationOptions);

            var authorityUrl = authenticationOptions.GetAuthorityUri();
            services.Configure<TokenValidationOptions>(options =>
            {
                options.AuthorityUrl = authorityUrl;
                options.EnableJWTRefreshToken = authenticationOptions.EnableJWTRefreshToken;
            });
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
                options.Events = authenticationOptions.Events;
                options.Authority = authenticationOptions.Authority;
            });

            services.AddSingleton<ITokenProvider, JwtTokenProvider>();
            services.AddSingleton<ITokenProvider, ReferenceTokenProvider>();
            services.AddSingleton<ITokenProviderFactory, TokenProviderFactory>();

            services.AddSingleton<RefreshTokenService>();
            services.AddSingleton<ConfigurationService>();
            services.AddSingleton<AuthenticationEndpointService>();

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
            var configurationService = serviceScope.ServiceProvider.GetRequiredService<ConfigurationService>();

            configurationService.InitializationConfiguration();
            return builder;
        }
    }
}
