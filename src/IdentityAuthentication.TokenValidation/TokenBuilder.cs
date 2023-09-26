using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
using System.Net.Mime;
using System.Security.Claims;
using System.Text;

namespace IdentityAuthentication.TokenValidation
{
    internal class TokenBuilder
    {
        public static StringContent EmptyContent => new(string.Empty, Encoding.UTF8, MediaTypeNames.Application.Json);

        public static TokenValidationResult BuildTokenSuccessResultAsync(string json)
        {
            var obj = JObject.Parse(json);
            var claims = new List<Claim>();

            var grantType = string.Empty;
            foreach (var item in obj)
            {
                if (item.Value == null) continue;

                var value = item.Value.ToString();
                if (item.Key.Equals(nameof(grantType), StringComparison.OrdinalIgnoreCase)) grantType = value;

                claims.Add(new Claim(item.Key, value));
            }

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
