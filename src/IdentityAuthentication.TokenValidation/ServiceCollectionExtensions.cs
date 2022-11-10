using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdentityAuthentication.TokenValidation
{
    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddAuthentication(this IServiceCollection services)
        {
            services.AddAuthentication(options =>
            {
                options.DefaultScheme = IdentityAuthenticationDefaults.AuthenticationScheme;
                options.DefaultAuthenticateScheme = IdentityAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = IdentityAuthenticationDefaults.AuthenticationScheme;
                options.DefaultForbidScheme = IdentityAuthenticationDefaults.AuthenticationScheme;
                options.DefaultSignInScheme = IdentityAuthenticationDefaults.AuthenticationScheme;
                options.DefaultSignOutScheme = IdentityAuthenticationDefaults.AuthenticationScheme;
            });
            return services;
        }
    }
}
