using IdentityAuthentication.Model;
using IdentityAuthentication.TokenValidation.Abstractions;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
using System.Security.Claims;

namespace IdentityAuthentication.TokenValidation.TokenProviders
{
    internal class TokenResultProvider : ITokenResultProvider
    {
        private readonly IRefreshTokenProvider _refreshTokenProvider;

        public TokenResultProvider(IRefreshTokenProvider refreshTokenProvider)
        {
            _refreshTokenProvider = refreshTokenProvider;
        }

        public async Task<TokenValidationResult> BuildTokenSuccessResultAsync(string json)
        {
            var obj = JObject.Parse(json);
            var claims = new List<Claim>();

            string grantType = string.Empty, expiration = string.Empty;
            foreach (var item in obj)
            {
                var value = item.Value.ToString();
                if (item.Key.Equals(nameof(grantType), StringComparison.OrdinalIgnoreCase)) grantType = value;
                if (item.Key.Equals(ClaimTypes.Expiration, StringComparison.OrdinalIgnoreCase)) expiration = value;

                claims.Add(new Claim(item.Key, value));
            }
            await _refreshTokenProvider.RefreshTokenAsync(expiration);

            var identity = new ClaimsIdentity(claims, grantType);
            var result = new TokenValidationResult
            {
                IsValid = true,
                ClaimsIdentity = identity,
            };
            return result;
        }
    }
}
