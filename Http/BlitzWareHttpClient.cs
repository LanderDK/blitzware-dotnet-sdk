// BlitzWare .NET SDK - HTTP Client for API Communication
// Copyright (c) 2025 BlitzWare. All rights reserved.

using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using BlitzWare.SDK.Models;
using BlitzWare.SDK.Utils;

#if NET6_0_OR_GREATER
using Microsoft.Extensions.Logging;
#endif

namespace BlitzWare.SDK.Http
{
    /// <summary>
    /// HTTP client for BlitzWare API communication
    /// </summary>
    public class BlitzWareHttpClient : IDisposable
    {
        private readonly HttpClient _httpClient;
        private readonly BlitzWareConfig _config;
        private readonly bool _ownsHttpClient;
        private readonly JsonSerializerOptions _jsonOptions;

#if NET6_0_OR_GREATER
        private readonly ILogger? _logger;
#endif

        /// <summary>
        /// Initialize BlitzWare HTTP client
        /// </summary>
        /// <param name="config">BlitzWare configuration</param>
        /// <param name="httpClient">Optional HTTP client (creates new if not provided)</param>
#if NET6_0_OR_GREATER
        /// <param name="logger">Optional logger for debugging</param>
        public BlitzWareHttpClient(BlitzWareConfig config, HttpClient? httpClient = null, ILogger? logger = null)
#else
        public BlitzWareHttpClient(BlitzWareConfig config, HttpClient? httpClient = null)
#endif
        {
            _config = config ?? throw new ArgumentNullException(nameof(config));

            if (httpClient == null)
            {
                // Create HttpClientHandler with credentials support
                var handler = new HttpClientHandler
                {
                    UseCookies = true, // Enable cookie container
                    UseDefaultCredentials = false, // Don't use Windows credentials
                    CookieContainer = new System.Net.CookieContainer() // Create cookie container
                };

                _httpClient = new HttpClient(handler);
                _ownsHttpClient = true;
            }
            else
            {
                _httpClient = httpClient;
                _ownsHttpClient = false;
            }

            // Configure HTTP client
            _httpClient.Timeout = TimeSpan.FromMilliseconds(_config.TimeoutMs);
            _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd(_config.UserAgent);

#if NET6_0_OR_GREATER
            _logger = logger;
#endif

            // Configure JSON options
            _jsonOptions = new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                PropertyNameCaseInsensitive = true,
                WriteIndented = false
            };
        }

        /// <summary>
        /// Exchange authorization code for tokens
        /// </summary>
        /// <param name="code">Authorization code</param>
        /// <param name="codeVerifier">PKCE code verifier</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Token response</returns>
        public async Task<TokenResponse> ExchangeCodeForTokensAsync(string code, string codeVerifier, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(code))
                throw new ArgumentException("Code cannot be null or empty", nameof(code));
            if (string.IsNullOrEmpty(codeVerifier))
                throw new ArgumentException("Code verifier cannot be null or empty", nameof(codeVerifier));

            var request = new TokenExchangeRequest
            {
                Code = code,
                ClientId = _config.ClientId,
                RedirectUri = _config.RedirectUri,
                CodeVerifier = codeVerifier
            };

            return await PostTokenRequestAsync(request, cancellationToken);
        }

        /// <summary>
        /// Refresh access token using refresh token
        /// </summary>
        /// <param name="refreshToken">Refresh token</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Token response</returns>
        public async Task<TokenResponse> RefreshTokenAsync(string refreshToken, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(refreshToken))
                throw new ArgumentException("Refresh token cannot be null or empty", nameof(refreshToken));

            var request = new RefreshTokenRequest
            {
                RefreshToken = refreshToken,
                ClientId = _config.ClientId
            };

            return await PostTokenRequestAsync(request, cancellationToken);
        }

        /// <summary>
        /// Get user information using access token
        /// </summary>
        /// <param name="accessToken">Access token</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>User information</returns>
        public async Task<BlitzWareUser> GetUserInfoAsync(string accessToken, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(accessToken))
                throw new ArgumentException("Access token cannot be null or empty", nameof(accessToken));

            try
            {
#if NET6_0_OR_GREATER
                _logger?.LogDebug("Getting user info from {Url}", _config.UserInfoUrl);
#endif

                // First validate the token using introspection
                var tokenValidation = await IntrospectTokenAsync(accessToken, "access_token", cancellationToken);

                if (!tokenValidation.Active)
                {
#if NET6_0_OR_GREATER
                    _logger?.LogWarning("Access token is not active during user info fetch");
#endif
                    throw new InvalidTokenException("Access token is not active");
                }

                // Build URL with access_token query parameter (matching Flutter/React Native SDKs)
                var urlBuilder = new UriBuilder(_config.UserInfoUrl);
                urlBuilder.Query = $"access_token={Uri.EscapeDataString(accessToken)}";

                using var request = new HttpRequestMessage(HttpMethod.Get, urlBuilder.Uri);
                // Note: Don't add Content-Type header for GET requests (it's a content header, not a request header)

                using var response = await _httpClient.SendAsync(request, cancellationToken);

                if (!response.IsSuccessStatusCode)
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
#if NET6_0_OR_GREATER
                    _logger?.LogError("Failed to get user info. Status: {StatusCode}, Content: {Content}", 
                        response.StatusCode, errorContent);
#endif
                    throw new UserInfoException($"Failed to get user info: {response.StatusCode} - {errorContent}");
                }

                var content = await response.Content.ReadAsStringAsync();
                var user = JsonSerializer.Deserialize<BlitzWareUser>(content, _jsonOptions);

                if (user == null)
                    throw new UserInfoException("Failed to deserialize user info response");

#if NET6_0_OR_GREATER
                _logger?.LogDebug("Successfully retrieved user info for user {UserId}", user.Id);
#endif

                return user;
            }
            catch (HttpRequestException ex)
            {
                throw new NetworkException("Failed to retrieve user info", ex);
            }
            catch (TaskCanceledException ex) when (ex.InnerException is TimeoutException)
            {
                throw new NetworkException("Request timeout while retrieving user info", ex);
            }
            catch (JsonException ex)
            {
                throw new UserInfoException("Failed to parse user info response", ex);
            }
        }

        /// <summary>
        /// Revoke a token (logout)
        /// </summary>
        /// <param name="token">Token to revoke (access or refresh token)</param>
        /// <param name="tokenTypeHint">Hint about the token type ("access_token" or "refresh_token")</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>True if successful</returns>
        public async Task<bool> RevokeTokenAsync(string token, string? tokenTypeHint = null, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(token))
                throw new ArgumentException("Token cannot be null or empty", nameof(token));

            try
            {
                var revokeUrl = "https://auth.blitzware.xyz/api/auth/revoke";

#if NET6_0_OR_GREATER
                _logger?.LogDebug("Revoking token at {Url}", revokeUrl);
#endif

                var parameters = new Dictionary<string, string>
                {
                    ["token"] = token,
                    ["client_id"] = _config.ClientId
                };

                if (!string.IsNullOrEmpty(tokenTypeHint))
                {
                    parameters["token_type_hint"] = tokenTypeHint;
                }

                var formContent = OAuthUtils.CreateFormContent(parameters);
                using var content = new StringContent(formContent, Encoding.UTF8, "application/x-www-form-urlencoded");
                using var response = await _httpClient.PostAsync(revokeUrl, content, cancellationToken);

                // Token revocation typically returns 200 even if the token was already invalid
                var success = response.IsSuccessStatusCode;

#if NET6_0_OR_GREATER
                _logger?.LogDebug("Token revocation result: {Success} (Status: {StatusCode})", success, response.StatusCode);
#endif

                return success;
            }
            catch (HttpRequestException ex)
            {
                throw new NetworkException("Failed to revoke token", ex);
            }
            catch (TaskCanceledException ex) when (ex.InnerException is TimeoutException)
            {
                throw new NetworkException("Request timeout while revoking token", ex);
            }
        }

        /// <summary>
        /// Call the logout endpoint to end the user session on the server
        /// </summary>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Task representing the async operation</returns>
        public async Task LogoutAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                var logoutUrl = _config.LogoutUrl;

#if NET6_0_OR_GREATER
                _logger?.LogDebug("Calling logout endpoint at {Url}", logoutUrl);
#endif

                var requestBody = new
                {
                    client_id = _config.ClientId
                };

                var jsonContent = JsonSerializer.Serialize(requestBody, _jsonOptions);
                using var content = new StringContent(jsonContent, Encoding.UTF8, "application/json");
                using var response = await _httpClient.PostAsync(logoutUrl, content, cancellationToken);

                if (!response.IsSuccessStatusCode)
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
#if NET6_0_OR_GREATER
                    _logger?.LogWarning("Logout request failed. Status: {StatusCode}, Content: {Content}", 
                        response.StatusCode, errorContent);
#endif
                }
                else
                {
#if NET6_0_OR_GREATER
                    _logger?.LogDebug("Logout request successful");
#endif
                }
            }
            catch (HttpRequestException ex)
            {
                throw new NetworkException("Failed to call logout endpoint", ex);
            }
            catch (TaskCanceledException ex) when (ex.InnerException is TimeoutException)
            {
                throw new NetworkException("Request timeout while calling logout endpoint", ex);
            }
        }

        /// <summary>
        /// Validate an access token by attempting to get user info
        /// </summary>
        /// <param name="accessToken">Access token to validate</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>True if token is valid</returns>
        public async Task<bool> ValidateTokenAsync(string accessToken, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(accessToken))
                return false;

            try
            {
                await GetUserInfoAsync(accessToken, cancellationToken);
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Post a token request (exchange or refresh)
        /// </summary>
        /// <param name="request">Token request object</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Token response</returns>
        private async Task<TokenResponse> PostTokenRequestAsync(object request, CancellationToken cancellationToken)
        {
            try
            {
#if NET6_0_OR_GREATER
                _logger?.LogDebug("Posting token request to {Url}", _config.TokenUrl);
#endif

                // Convert request object to form parameters
                var json = JsonSerializer.Serialize(request, _jsonOptions);
                var parameters = JsonSerializer.Deserialize<Dictionary<string, string>>(json) ?? new Dictionary<string, string>();

                var formContent = OAuthUtils.CreateFormContent(parameters);
                using var content = new StringContent(formContent, Encoding.UTF8, "application/x-www-form-urlencoded");

                if (_config.EnableLogging)
                {
#if NET6_0_OR_GREATER
                    _logger?.LogDebug("Token request form data: {FormData}", formContent);
#endif
                }

                using var response = await _httpClient.PostAsync(_config.TokenUrl, content, cancellationToken);

                var responseContent = await response.Content.ReadAsStringAsync();

                if (!response.IsSuccessStatusCode)
                {
#if NET6_0_OR_GREATER
                    _logger?.LogError("Token request failed. Status: {StatusCode}, Content: {Content}", 
                        response.StatusCode, responseContent);
#endif
                    throw new AuthenticationFailedException($"Token request failed: {response.StatusCode} - {responseContent}");
                }

                var tokenResponse = JsonSerializer.Deserialize<TokenResponse>(responseContent, _jsonOptions);

                if (tokenResponse == null || string.IsNullOrEmpty(tokenResponse.AccessToken))
                    throw new AuthenticationFailedException("Invalid token response");

#if NET6_0_OR_GREATER
                _logger?.LogDebug("Token request successful. Token type: {TokenType}, Expires in: {ExpiresIn}s", 
                    tokenResponse.TokenType, tokenResponse.ExpiresIn);
#endif

                return tokenResponse;
            }
            catch (HttpRequestException ex)
            {
                throw new NetworkException("Failed to exchange token", ex);
            }
            catch (TaskCanceledException ex) when (ex.InnerException is TimeoutException)
            {
                throw new NetworkException("Request timeout during token exchange", ex);
            }
            catch (JsonException ex)
            {
                throw new AuthenticationFailedException("Failed to parse token response", ex);
            }
        }

        /// <summary>
        /// Make a generic authenticated API request
        /// </summary>
        /// <typeparam name="T">Response type</typeparam>
        /// <param name="method">HTTP method</param>
        /// <param name="url">Request URL</param>
        /// <param name="accessToken">Access token</param>
        /// <param name="body">Optional request body</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Deserialized response</returns>
        public async Task<T?> MakeAuthenticatedRequestAsync<T>(HttpMethod method, string url, string accessToken, object? body = null, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(url))
                throw new ArgumentException("URL cannot be null or empty", nameof(url));
            if (string.IsNullOrEmpty(accessToken))
                throw new ArgumentException("Access token cannot be null or empty", nameof(accessToken));

            try
            {
                using var request = new HttpRequestMessage(method, url);
                request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

                if (body != null)
                {
                    var json = JsonSerializer.Serialize(body, _jsonOptions);
                    request.Content = new StringContent(json, Encoding.UTF8, "application/json");
                }

                using var response = await _httpClient.SendAsync(request, cancellationToken);

                if (!response.IsSuccessStatusCode)
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    throw new NetworkException($"API request failed: {response.StatusCode} - {errorContent}");
                }

                var content = await response.Content.ReadAsStringAsync();
                
                if (typeof(T) == typeof(string))
                    return (T)(object)content;

                return JsonSerializer.Deserialize<T>(content, _jsonOptions);
            }
            catch (HttpRequestException ex)
            {
                throw new NetworkException("Network error during API request", ex);
            }
            catch (TaskCanceledException ex) when (ex.InnerException is TimeoutException)
            {
                throw new NetworkException("Request timeout during API request", ex);
            }
            catch (JsonException ex)
            {
                throw new NetworkException("Failed to parse API response", ex);
            }
        }

        /// <summary>
        /// Health check - verify BlitzWare domain is accessible
        /// </summary>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>True if domain is accessible</returns>
        public async Task<bool> HealthCheckAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                var healthUrl = "https://auth.blitzware.xyz/api/auth/.well-known/openid_configuration";
                using var response = await _httpClient.GetAsync(healthUrl, cancellationToken);
                return response.IsSuccessStatusCode;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Get OpenID Connect configuration
        /// </summary>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>OIDC configuration</returns>
        public async Task<Dictionary<string, object>?> GetOidcConfigurationAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                var configUrl = "https://auth.blitzware.xyz/api/auth/.well-known/openid_configuration";
                using var response = await _httpClient.GetAsync(configUrl, cancellationToken);

                if (!response.IsSuccessStatusCode)
                    return null;

                var content = await response.Content.ReadAsStringAsync();
                return JsonSerializer.Deserialize<Dictionary<string, object>>(content, _jsonOptions);
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Introspect a token to check its validity and get metadata (RFC 7662)
        /// </summary>
        /// <param name="token">Token to introspect</param>
        /// <param name="tokenTypeHint">Type hint: "access_token" or "refresh_token"</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Token introspection response</returns>
        public async Task<TokenIntrospectionResponse> IntrospectTokenAsync(string token, string? tokenTypeHint = null, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(token))
                throw new ArgumentException("Token cannot be null or empty", nameof(token));

            try
            {
                var introspectUrl = "https://auth.blitzware.xyz/api/auth/introspect";

#if NET6_0_OR_GREATER
                _logger?.LogDebug("Introspecting token at {Url}", introspectUrl);
#endif

                var parameters = new Dictionary<string, string>
                {
                    ["token"] = token,
                    ["client_id"] = _config.ClientId
                };

                if (!string.IsNullOrEmpty(tokenTypeHint))
                {
                    parameters["token_type_hint"] = tokenTypeHint;
                }

                var json = JsonSerializer.Serialize(parameters, _jsonOptions);
                using var content = new StringContent(json, Encoding.UTF8, "application/json");
                using var response = await _httpClient.PostAsync(introspectUrl, content, cancellationToken);

                if (!response.IsSuccessStatusCode)
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
#if NET6_0_OR_GREATER
                    _logger?.LogError("Token introspection failed. Status: {StatusCode}, Content: {Content}", 
                        response.StatusCode, errorContent);
#endif
                    throw new NetworkException($"Token introspection failed: {response.StatusCode} - {errorContent}");
                }

                var responseContent = await response.Content.ReadAsStringAsync();
                var introspectionResponse = JsonSerializer.Deserialize<TokenIntrospectionResponse>(responseContent, _jsonOptions);

                if (introspectionResponse == null)
                    throw new NetworkException("Failed to deserialize introspection response");

#if NET6_0_OR_GREATER
                _logger?.LogDebug("Token introspection result: Active={Active}", introspectionResponse.Active);
#endif

                return introspectionResponse;
            }
            catch (HttpRequestException ex)
            {
                throw new NetworkException("Failed to introspect token", ex);
            }
            catch (TaskCanceledException ex) when (ex.InnerException is TimeoutException)
            {
                throw new NetworkException("Request timeout during token introspection", ex);
            }
            catch (JsonException ex)
            {
                throw new NetworkException("Failed to parse introspection response", ex);
            }
        }

        /// <summary>
        /// Dispose resources
        /// </summary>
        public void Dispose()
        {
            if (_ownsHttpClient)
            {
                _httpClient?.Dispose();
            }
        }
    }

    /// <summary>
    /// HTTP client factory for BlitzWare clients
    /// </summary>
    public static class BlitzWareHttpClientFactory
    {
        /// <summary>
        /// Create a configured HTTP client for BlitzWare
        /// </summary>
        /// <param name="config">BlitzWare configuration</param>
        /// <returns>Configured HTTP client</returns>
        public static HttpClient CreateHttpClient(BlitzWareConfig config)
        {
            var httpClient = new HttpClient();
            ConfigureHttpClient(httpClient, config);
            return httpClient;
        }

        /// <summary>
        /// Configure an existing HTTP client for BlitzWare
        /// </summary>
        /// <param name="httpClient">HTTP client to configure</param>
        /// <param name="config">BlitzWare configuration</param>
        public static void ConfigureHttpClient(HttpClient httpClient, BlitzWareConfig config)
        {
            if (httpClient == null)
                throw new ArgumentNullException(nameof(httpClient));
            if (config == null)
                throw new ArgumentNullException(nameof(config));

            httpClient.Timeout = TimeSpan.FromMilliseconds(config.TimeoutMs);
            
            // Clear and set user agent
            httpClient.DefaultRequestHeaders.UserAgent.Clear();
            httpClient.DefaultRequestHeaders.UserAgent.ParseAdd(config.UserAgent);

            // Set common headers
            httpClient.DefaultRequestHeaders.Accept.Clear();
            httpClient.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));
        }
    }
}