// BlitzWare .NET SDK - OAuth Utilities with PKCE Support
// Copyright (c) 2025 BlitzWare. All rights reserved.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading.Tasks;
using System.Web;
using BlitzWare.SDK.Models;

#if NET6_0_OR_GREATER
using System.Buffers;
#endif

namespace BlitzWare.SDK.Utils
{
    /// <summary>
    /// OAuth utilities for BlitzWare authentication with PKCE support
    /// </summary>
    public static class OAuthUtils
    {
        private static readonly Random _random = new Random();
        private const string ValidChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";

        /// <summary>
        /// Generate a cryptographically secure random string
        /// </summary>
        /// <param name="length">Length of the random string</param>
        /// <param name="useUrlSafeChars">Whether to use URL-safe characters only</param>
        /// <returns>Random string</returns>
        public static string GenerateRandomString(int length = 43, bool useUrlSafeChars = true)
        {
            if (length <= 0)
                throw new ArgumentException("Length must be positive", nameof(length));

            var chars = useUrlSafeChars ? ValidChars : ValidChars + "+/";
            var buffer = new char[length];

#if NET6_0_OR_GREATER
            using var rng = RandomNumberGenerator.Create();
            var bytes = new byte[length];
            rng.GetBytes(bytes);

            for (int i = 0; i < length; i++)
            {
                buffer[i] = chars[bytes[i] % chars.Length];
            }
#else
            // Fallback for .NET Standard 2.0
            for (int i = 0; i < length; i++)
            {
                buffer[i] = chars[_random.Next(chars.Length)];
            }
#endif

            return new string(buffer);
        }

        /// <summary>
        /// Generate PKCE (Proof Key for Code Exchange) data
        /// </summary>
        /// <returns>PKCE data with code verifier and challenge</returns>
        public static PKCEData GeneratePKCE()
        {
            var codeVerifier = GenerateRandomString(128);
            var codeChallenge = GenerateCodeChallenge(codeVerifier);

            return new PKCEData
            {
                CodeVerifier = codeVerifier,
                CodeChallenge = codeChallenge,
                CodeChallengeMethod = "S256"
            };
        }

        /// <summary>
        /// Generate a code challenge from a code verifier using SHA256
        /// </summary>
        /// <param name="codeVerifier">The code verifier</param>
        /// <returns>Base64 URL-encoded SHA256 hash of the code verifier</returns>
        public static string GenerateCodeChallenge(string codeVerifier)
        {
            if (string.IsNullOrEmpty(codeVerifier))
                throw new ArgumentException("Code verifier cannot be null or empty", nameof(codeVerifier));

            using var sha256 = SHA256.Create();
            var challengeBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
            return Base64UrlEncode(challengeBytes);
        }

        /// <summary>
        /// Generate a secure state parameter for OAuth
        /// </summary>
        /// <returns>Random state string</returns>
        public static string GenerateState()
        {
            return GenerateRandomString(32);
        }

        /// <summary>
        /// Generate a nonce for OpenID Connect
        /// </summary>
        /// <returns>Random nonce string</returns>
        public static string GenerateNonce()
        {
            return GenerateRandomString(32);
        }

        /// <summary>
        /// Encode a byte array to Base64 URL format
        /// </summary>
        /// <param name="input">Input bytes</param>
        /// <returns>Base64 URL encoded string</returns>
        public static string Base64UrlEncode(byte[] input)
        {
            if (input == null)
                throw new ArgumentNullException(nameof(input));

#if NET6_0_OR_GREATER
            return Convert.ToBase64String(input)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
#else
            var base64 = Convert.ToBase64String(input);
            return base64.Split('=')[0]
                .Replace('+', '-')
                .Replace('/', '_');
#endif
        }

        /// <summary>
        /// Decode a Base64 URL formatted string
        /// </summary>
        /// <param name="input">Base64 URL encoded string</param>
        /// <returns>Decoded bytes</returns>
        public static byte[] Base64UrlDecode(string input)
        {
            if (string.IsNullOrEmpty(input))
                throw new ArgumentException("Input cannot be null or empty", nameof(input));

            var output = input.Replace('-', '+').Replace('_', '/');
            switch (output.Length % 4)
            {
                case 2: output += "=="; break;
                case 3: output += "="; break;
            }

            return Convert.FromBase64String(output);
        }

        /// <summary>
        /// Build OAuth authorization URL
        /// </summary>
        /// <param name="config">BlitzWare configuration</param>
        /// <param name="pkceData">PKCE data</param>
        /// <param name="state">State parameter</param>
        /// <param name="nonce">Optional nonce for OpenID Connect</param>
        /// <returns>Authorization URL</returns>
        public static string BuildAuthorizationUrl(BlitzWareConfig config, PKCEData pkceData, string state, string? nonce = null)
        {
            if (config == null)
                throw new ArgumentNullException(nameof(config));
            if (pkceData == null)
                throw new ArgumentNullException(nameof(pkceData));
            if (string.IsNullOrEmpty(state))
                throw new ArgumentException("State cannot be null or empty", nameof(state));

            var parameters = new Dictionary<string, string>
            {
                ["response_type"] = "code",
                ["client_id"] = config.ClientId,
                ["redirect_uri"] = config.RedirectUri,
                ["state"] = state,
                ["code_challenge"] = pkceData.CodeChallenge,
                ["code_challenge_method"] = pkceData.CodeChallengeMethod
            };

            if (!string.IsNullOrEmpty(nonce))
            {
                parameters["nonce"] = nonce;
            }

            // Add any additional parameters
            foreach (var kvp in config.AdditionalParameters)
            {
                parameters[kvp.Key] = kvp.Value;
            }

            var queryString = string.Join("&", parameters.Select(kvp =>
                $"{Uri.EscapeDataString(kvp.Key)}={Uri.EscapeDataString(kvp.Value)}"));

            return $"{config.AuthorizationUrl}?{queryString}";
        }

        /// <summary>
        /// Parse callback URL to extract authorization response
        /// </summary>
        /// <param name="callbackUrl">The callback URL</param>
        /// <returns>Authorization response</returns>
        public static AuthorizationResponse ParseCallbackUrl(string callbackUrl)
        {
            if (string.IsNullOrEmpty(callbackUrl))
                throw new ArgumentException("Callback URL cannot be null or empty", nameof(callbackUrl));

            try
            {
                var uri = new Uri(callbackUrl);
                var query = HttpUtility.ParseQueryString(uri.Query);

                var response = new AuthorizationResponse();

                if (query["error"] != null)
                {
                    response.IsSuccess = false;
                    response.Error = query["error"];
                    response.ErrorDescription = query["error_description"];
                }
                else
                {
                    response.IsSuccess = true;
                    response.Code = query["code"];
                    response.State = query["state"];
                }

                return response;
            }
            catch (Exception ex)
            {
                return new AuthorizationResponse
                {
                    IsSuccess = false,
                    Error = "invalid_request",
                    ErrorDescription = $"Failed to parse callback URL: {ex.Message}"
                };
            }
        }

        /// <summary>
        /// Build logout URL
        /// </summary>
        /// <param name="config">BlitzWare configuration</param>
        /// <param name="returnTo">Optional return URL after logout</param>
        /// <returns>Logout URL</returns>
        public static string BuildLogoutUrl(BlitzWareConfig config, string? returnTo = null)
        {
            if (config == null)
                throw new ArgumentNullException(nameof(config));

            var url = config.LogoutUrl;

            var parameters = new List<string>
            {
                $"client_id={Uri.EscapeDataString(config.ClientId)}"
            };

            if (!string.IsNullOrEmpty(returnTo))
            {
                parameters.Add($"returnTo={Uri.EscapeDataString(returnTo)}");
            }

            if (parameters.Count > 0)
            {
                url += "?" + string.Join("&", parameters);
            }

            return url;
        }

        /// <summary>
        /// Validate state parameter to prevent CSRF attacks
        /// </summary>
        /// <param name="expectedState">Expected state value</param>
        /// <param name="actualState">Actual state value from response</param>
        /// <returns>True if states match</returns>
        public static bool ValidateState(string expectedState, string? actualState)
        {
            if (string.IsNullOrEmpty(expectedState))
                return false;

            return string.Equals(expectedState, actualState, StringComparison.Ordinal);
        }

        /// <summary>
        /// Create form-encoded content for token exchange
        /// </summary>
        /// <param name="parameters">Parameters to encode</param>
        /// <returns>Form-encoded string</returns>
        public static string CreateFormContent(Dictionary<string, string> parameters)
        {
            if (parameters == null)
                throw new ArgumentNullException(nameof(parameters));

            return string.Join("&", parameters.Select(kvp =>
                $"{Uri.EscapeDataString(kvp.Key)}={Uri.EscapeDataString(kvp.Value)}"));
        }

        /// <summary>
        /// Extract domain from client ID (if follows BlitzWare convention)
        /// </summary>
        /// <param name="clientId">Client ID</param>
        /// <returns>Extracted domain or null</returns>
        public static string? ExtractDomainFromClientId(string clientId)
        {
            if (string.IsNullOrEmpty(clientId))
                return null;

            // BlitzWare client IDs might follow pattern: domain_appname_randomstring
            var parts = clientId.Split('_');
            if (parts.Length >= 2)
            {
                return parts[0];
            }

            return null;
        }

        /// <summary>
        /// Get authorization header value for Bearer token
        /// </summary>
        /// <param name="accessToken">Access token</param>
        /// <returns>Authorization header value</returns>
        public static string GetBearerAuthHeader(string accessToken)
        {
            if (string.IsNullOrEmpty(accessToken))
                throw new ArgumentException("Access token cannot be null or empty", nameof(accessToken));

            return $"Bearer {accessToken}";
        }

        /// <summary>
        /// Parse JWT token without verification (for reading claims)
        /// WARNING: This does not verify the token signature. Only use for reading public claims.
        /// </summary>
        /// <param name="token">JWT token</param>
        /// <returns>Parsed claims as dictionary</returns>
        public static Dictionary<string, object>? ParseJwtClaims(string token)
        {
            if (string.IsNullOrEmpty(token))
                return null;

            try
            {
                var parts = token.Split('.');
                if (parts.Length != 3)
                    return null;

                var payload = parts[1];
                var payloadBytes = Base64UrlDecode(payload);
                var payloadJson = Encoding.UTF8.GetString(payloadBytes);

                return JsonSerializer.Deserialize<Dictionary<string, object>>(payloadJson);
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Get token expiry from JWT claims
        /// </summary>
        /// <param name="token">JWT token</param>
        /// <returns>Expiry time or null if not found</returns>
        public static DateTime? GetTokenExpiry(string token)
        {
            var claims = ParseJwtClaims(token);
            if (claims?.TryGetValue("exp", out var expObj) == true)
            {
                if (expObj is JsonElement element && element.ValueKind == JsonValueKind.Number)
                {
                    var exp = element.GetInt64();
                    return DateTimeOffset.FromUnixTimeSeconds(exp).DateTime;
                }
            }

            return null;
        }

        /// <summary>
        /// Check if JWT token is expired
        /// </summary>
        /// <param name="token">JWT token</param>
        /// <param name="clockSkew">Clock skew tolerance (default: 5 minutes)</param>
        /// <returns>True if token is expired</returns>
        public static bool IsTokenExpired(string token, TimeSpan? clockSkew = null)
        {
            var expiry = GetTokenExpiry(token);
            if (!expiry.HasValue)
                return true; // Assume expired if no expiry claim

            var skew = clockSkew ?? TimeSpan.FromMinutes(5);
            return DateTime.UtcNow > expiry.Value.Add(skew);
        }

        /// <summary>
        /// Generate a secure redirect URI for OAuth flow
        /// </summary>
        /// <param name="scheme">Custom URL scheme</param>
        /// <param name="host">Host (default: oauth)</param>
        /// <param name="path">Path (default: callback)</param>
        /// <returns>Redirect URI</returns>
        public static string GenerateRedirectUri(string scheme, string host = "oauth", string path = "callback")
        {
            if (string.IsNullOrEmpty(scheme))
                throw new ArgumentException("Scheme cannot be null or empty", nameof(scheme));

            return $"{scheme}://{host}/{path}";
        }

        /// <summary>
        /// Validate redirect URI format
        /// </summary>
        /// <param name="redirectUri">Redirect URI to validate</param>
        /// <returns>True if valid</returns>
        public static bool IsValidRedirectUri(string redirectUri)
        {
            if (string.IsNullOrEmpty(redirectUri))
                return false;

            return Uri.TryCreate(redirectUri, UriKind.Absolute, out var uri) &&
                   (uri.Scheme == "http" || uri.Scheme == "https" || IsCustomScheme(uri.Scheme));
        }

        /// <summary>
        /// Check if scheme is a custom scheme (not http/https)
        /// </summary>
        /// <param name="scheme">URL scheme</param>
        /// <returns>True if custom scheme</returns>
        public static bool IsCustomScheme(string scheme)
        {
            return !string.IsNullOrEmpty(scheme) &&
                   scheme != "http" &&
                   scheme != "https" &&
                   scheme != "file" &&
                   scheme != "ftp";
        }

        /// <summary>
        /// Create a deep link URL for mobile apps
        /// </summary>
        /// <param name="scheme">App's custom URL scheme</param>
        /// <param name="host">Host (default: auth)</param>
        /// <param name="action">Action (default: login)</param>
        /// <param name="parameters">Additional parameters</param>
        /// <returns>Deep link URL</returns>
        public static string CreateDeepLink(string scheme, string host = "auth", string action = "login", Dictionary<string, string>? parameters = null)
        {
            if (string.IsNullOrEmpty(scheme))
                throw new ArgumentException("Scheme cannot be null or empty", nameof(scheme));

            var url = $"{scheme}://{host}/{action}";

            if (parameters?.Count > 0)
            {
                var queryString = string.Join("&", parameters.Select(kvp =>
                    $"{Uri.EscapeDataString(kvp.Key)}={Uri.EscapeDataString(kvp.Value)}"));
                url += "?" + queryString;
            }

            return url;
        }
    }

    /// <summary>
    /// Helper methods for working with scopes
    /// </summary>
    public static class ScopeUtils
    {
        /// <summary>
        /// Parse scope string into list
        /// </summary>
        /// <param name="scopeString">Space-separated scope string</param>
        /// <returns>List of scopes</returns>
        public static List<string> ParseScopes(string? scopeString)
        {
            if (string.IsNullOrWhiteSpace(scopeString))
                return new List<string>();

            return scopeString.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries)
                             .ToList();
        }

        /// <summary>
        /// Join scopes into a space-separated string
        /// </summary>
        /// <param name="scopes">List of scopes</param>
        /// <returns>Space-separated scope string</returns>
        public static string JoinScopes(IEnumerable<string> scopes)
        {
            if (scopes == null)
                return string.Empty;

            return string.Join(" ", scopes.Where(s => !string.IsNullOrWhiteSpace(s)));
        }

        /// <summary>
        /// Check if scope list contains a specific scope
        /// </summary>
        /// <param name="scopes">List of scopes</param>
        /// <param name="scope">Scope to check</param>
        /// <returns>True if scope is present</returns>
        public static bool HasScope(IEnumerable<string> scopes, string scope)
        {
            if (scopes == null || string.IsNullOrEmpty(scope))
                return false;

            return scopes.Contains(scope, StringComparer.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Add scope to list if not already present
        /// </summary>
        /// <param name="scopes">List of scopes to modify</param>
        /// <param name="scope">Scope to add</param>
        public static void AddScope(List<string> scopes, string scope)
        {
            if (scopes == null || string.IsNullOrEmpty(scope))
                return;

            if (!HasScope(scopes, scope))
            {
                scopes.Add(scope);
            }
        }

        /// <summary>
        /// Remove scope from list
        /// </summary>
        /// <param name="scopes">List of scopes to modify</param>
        /// <param name="scope">Scope to remove</param>
        public static void RemoveScope(List<string> scopes, string scope)
        {
            if (scopes == null || string.IsNullOrEmpty(scope))
                return;

            scopes.RemoveAll(s => string.Equals(s, scope, StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>
        /// Get standard scopes for authentication
        /// </summary>
        /// <param name="includeRoles">Include roles scope</param>
        /// <param name="includeOfflineAccess">Include offline_access scope</param>
        /// <returns>List of standard scopes</returns>
        public static List<string> GetStandardScopes(bool includeRoles = true, bool includeOfflineAccess = false)
        {
            var scopes = new List<string> { BlitzWareScopes.OpenId, BlitzWareScopes.Profile, BlitzWareScopes.Email };

            if (includeRoles)
            {
                scopes.Add(BlitzWareScopes.Roles);
            }

            if (includeOfflineAccess)
            {
                scopes.Add(BlitzWareScopes.OfflineAccess);
            }

            return scopes;
        }
    }
}