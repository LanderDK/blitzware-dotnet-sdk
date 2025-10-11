// BlitzWare .NET SDK - Main Authentication Client
// Copyright (c) 2025 BlitzWare. All rights reserved.

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using BlitzWare.SDK.Models;
using BlitzWare.SDK.Storage;
using BlitzWare.SDK.Http;
using BlitzWare.SDK.Utils;

#if NET6_0_OR_GREATER
using Microsoft.Extensions.Logging;
#endif

namespace BlitzWare.SDK
{
    /// <summary>
    /// Main BlitzWare authentication client for .NET applications
    /// Provides OAuth 2.0 with PKCE authentication, token management, and user info retrieval
    /// </summary>
    public class BlitzWareAuth : IDisposable
    {
        private readonly BlitzWareConfig _config;
        private readonly ISecureStorage _storage;
        private readonly BlitzWareHttpClient _httpClient;
        private readonly string _storageKeyPrefix;

#if NET6_0_OR_GREATER
        private readonly ILogger? _logger;
#endif

        private BlitzWareUser? _currentUser;
        private TokenResponse? _currentTokens;
        private AuthState _currentState = AuthState.Loading;

        /// <summary>
        /// Event fired when authentication state changes
        /// </summary>
        public event EventHandler<AuthStateChangedEventArgs>? AuthStateChanged;

        /// <summary>
        /// Initialize BlitzWare authentication client
        /// </summary>
        /// <param name="config">BlitzWare configuration</param>
        /// <param name="storage">Secure storage implementation (optional, uses auto-detection if not provided)</param>
#if NET6_0_OR_GREATER
        /// <param name="logger">Optional logger for debugging</param>
        public BlitzWareAuth(BlitzWareConfig config, ISecureStorage? storage = null, ILogger? logger = null)
#else
        public BlitzWareAuth(BlitzWareConfig config, ISecureStorage? storage = null)
#endif
        {
            _config = config ?? throw new ArgumentNullException(nameof(config));

            var validation = _config.Validate();
            if (!validation.IsValid)
                throw new ConfigurationException($"Invalid configuration: {string.Join(", ", validation.Errors)}");

            _storage = storage ?? new AutoSecureStorage();
            _storageKeyPrefix = StorageKeys.GetClientKey("", _config.ClientId);

#if NET6_0_OR_GREATER
            _logger = logger;
            _httpClient = new BlitzWareHttpClient(_config, logger: _logger);
#else
            _httpClient = new BlitzWareHttpClient(_config);
#endif

#if NET6_0_OR_GREATER
            _logger?.LogInformation("BlitzWare Auth initialized for client {ClientId} using {StorageType}",
                _config.ClientId, _storage.StorageType);
#endif
        }

        /// <summary>
        /// Current authentication state
        /// </summary>
        public AuthState State => _currentState;

        /// <summary>
        /// Current authenticated user (null if not authenticated)
        /// </summary>
        public BlitzWareUser? User => _currentUser;

        /// <summary>
        /// Whether the user is currently authenticated
        /// </summary>
        public bool IsAuthenticated => _currentState == AuthState.Authenticated && _currentUser != null;

        /// <summary>
        /// BlitzWare configuration
        /// </summary>
        public BlitzWareConfig Config => _config;

        /// <summary>
        /// Initialize the authentication client by checking for existing tokens
        /// Call this method when your application starts
        /// </summary>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Task representing the async operation</returns>
        public async Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            try
            {
#if NET6_0_OR_GREATER
                _logger?.LogDebug("Initializing BlitzWare Auth...");
#endif

                UpdateState(AuthState.Loading);

                // Check for existing tokens
                var tokens = await _storage.GetTokenResponseAsync(_storageKeyPrefix);
                if (tokens != null && !string.IsNullOrEmpty(tokens.AccessToken))
                {
                    // Validate and potentially refresh the tokens
                    var isValid = await ValidateAndRefreshTokensAsync(tokens, cancellationToken);
                    if (isValid)
                    {
                        await LoadUserInfoAsync(cancellationToken);
                        UpdateState(AuthState.Authenticated, _currentUser);
                        return;
                    }
                }

                // No valid tokens found
                UpdateState(AuthState.Unauthenticated);

#if NET6_0_OR_GREATER
                _logger?.LogDebug("BlitzWare Auth initialization completed. State: {State}", _currentState);
#endif
            }
            catch (Exception ex)
            {
#if NET6_0_OR_GREATER
                _logger?.LogError(ex, "Error during BlitzWare Auth initialization");
#endif
                UpdateState(AuthState.Error, error: ex);
            }
        }

        /// <summary>
        /// Start the OAuth login flow
        /// Returns the authorization URL that should be opened in a browser
        /// </summary>
        /// <param name="additionalParameters">Additional OAuth parameters</param>
        /// <returns>Authentication request with authorization URL</returns>
        public async Task<AuthRequest> StartLoginAsync(Dictionary<string, string>? additionalParameters = null)
        {
            try
            {
#if NET6_0_OR_GREATER
                _logger?.LogDebug("Starting OAuth login flow");
#endif

                // Generate PKCE data
                var pkceData = OAuthUtils.GeneratePKCE();
                var state = OAuthUtils.GenerateState();
                var nonce = OAuthUtils.GenerateNonce();

                // Store PKCE data and state for later verification
                await _storage.SetAsync($"{_storageKeyPrefix}{StorageKeys.PKCECodeVerifier}", pkceData.CodeVerifier);
                await _storage.SetAsync($"{_storageKeyPrefix}{StorageKeys.AuthState}", state);
                await _storage.SetAsync($"{_storageKeyPrefix}{StorageKeys.AuthNonce}", nonce);

                // Merge additional parameters with config
                var allParameters = new Dictionary<string, string>(_config.AdditionalParameters);
                if (additionalParameters != null)
                {
                    foreach (var kvp in additionalParameters)
                    {
                        allParameters[kvp.Key] = kvp.Value;
                    }
                }

                // Temporarily update config with merged parameters
                var tempConfig = new BlitzWareConfig
                {
                    ClientId = _config.ClientId,
                    RedirectUri = _config.RedirectUri,
                    ResponseType = _config.ResponseType
                };

                // Build authorization URL
                var authUrl = OAuthUtils.BuildAuthorizationUrl(tempConfig, pkceData, state, nonce);

                var authRequest = new AuthRequest
                {
                    AuthorizationUrl = authUrl,
                    PKCEData = pkceData,
                    State = state,
                    Nonce = nonce
                };

#if NET6_0_OR_GREATER
                _logger?.LogDebug("OAuth login flow started. Authorization URL generated.");
#endif

                return authRequest;
            }
            catch (Exception ex)
            {
#if NET6_0_OR_GREATER
                _logger?.LogError(ex, "Error starting OAuth login flow");
#endif
                throw new AuthenticationFailedException("Failed to start login flow", ex);
            }
        }

        /// <summary>
        /// Handle the OAuth callback and complete the authentication flow
        /// </summary>
        /// <param name="callbackUrl">The callback URL received from the OAuth provider</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Task representing the async operation</returns>
        public async Task HandleCallbackAsync(string callbackUrl, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(callbackUrl))
                throw new ArgumentException("Callback URL cannot be null or empty", nameof(callbackUrl));

            try
            {
#if NET6_0_OR_GREATER
                _logger?.LogDebug("Handling OAuth callback");
#endif

                UpdateState(AuthState.Loading);

                // Parse the callback URL
                var response = OAuthUtils.ParseCallbackUrl(callbackUrl);

                if (!response.IsSuccess)
                {
                    var error = $"OAuth error: {response.Error} - {response.ErrorDescription}";
                    throw new AuthenticationFailedException(error);
                }

                // Verify state parameter
                var expectedState = await _storage.GetAsync($"{_storageKeyPrefix}{StorageKeys.AuthState}");
                if (!OAuthUtils.ValidateState(expectedState, response.State))
                {
                    throw new AuthenticationFailedException("Invalid state parameter - possible CSRF attack");
                }

                // Get the stored code verifier
                var codeVerifier = await _storage.GetAsync($"{_storageKeyPrefix}{StorageKeys.PKCECodeVerifier}");
                if (string.IsNullOrEmpty(codeVerifier))
                {
                    throw new AuthenticationFailedException("Code verifier not found - invalid auth flow");
                }

                if (string.IsNullOrEmpty(response.Code))
                {
                    throw new AuthenticationFailedException("Authorization code not received");
                }

                // Exchange code for tokens
                var tokens = await _httpClient.ExchangeCodeForTokensAsync(response.Code, codeVerifier, cancellationToken);

                // Store tokens
                await StoreTokensAsync(tokens);

                // Get user info
                await LoadUserInfoAsync(cancellationToken);

                // Clean up temporary auth data
                await CleanupAuthDataAsync();

                UpdateState(AuthState.Authenticated, _currentUser);

#if NET6_0_OR_GREATER
                _logger?.LogInformation("OAuth callback handled successfully. User {UserId} authenticated.", _currentUser?.Id);
#endif
            }
            catch (Exception ex)
            {
#if NET6_0_OR_GREATER
                _logger?.LogError(ex, "Error handling OAuth callback");
#endif
                UpdateState(AuthState.Error, error: ex);
                throw;
            }
        }

        /// <summary>
        /// Get a valid access token, refreshing if necessary
        /// </summary>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Valid access token or null if not authenticated</returns>
        public async Task<string?> GetAccessTokenAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                // First check if we have a token locally that appears valid
                if (_currentTokens == null || string.IsNullOrEmpty(_currentTokens.AccessToken))
                    return null;

                // Check if token is expired locally
                if (_currentTokens.IsExpired)
                {
                    // Token is expired locally, try to refresh
                    if (!string.IsNullOrEmpty(_currentTokens.RefreshToken))
                    {
                        try
                        {
                            await RefreshTokensAsync(cancellationToken);
                            return _currentTokens?.AccessToken;
                        }
                        catch
                        {
                            return null;
                        }
                    }
                    return null;
                }

                // Now validate with server to be sure
                var isValid = await IsAuthenticatedAsync(cancellationToken);
                if (!isValid)
                {
                    // Server says token is invalid, try to refresh
                    if (!string.IsNullOrEmpty(_currentTokens.RefreshToken))
                    {
                        try
                        {
                            await RefreshTokensAsync(cancellationToken);
                            return _currentTokens?.AccessToken;
                        }
                        catch
                        {
                            return null;
                        }
                    }
                    return null;
                }

                return _currentTokens.AccessToken;
            }
            catch (Exception ex)
            {
#if NET6_0_OR_GREATER
                _logger?.LogError(ex, "Error getting access token");
#endif
                return null;
            }
        }

        /// <summary>
        /// Get current access token without validation (faster, but may be expired)
        /// Use this for non-critical operations or when you handle validation separately
        /// </summary>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Access token or null</returns>
        public async Task<string?> GetAccessTokenFastAsync(CancellationToken cancellationToken = default)
        {
            if (_currentTokens == null || string.IsNullOrEmpty(_currentTokens.AccessToken))
                return null;

            // Check if token is expired locally
            if (_currentTokens.IsExpired)
                return null;

            return _currentTokens.AccessToken;
        }

        /// <summary>
        /// Check if user is currently authenticated by validating token with server
        /// Uses token introspection (RFC 7662)
        /// </summary>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>True if authenticated</returns>
        public async Task<bool> IsAuthenticatedAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                if (_currentTokens == null || string.IsNullOrEmpty(_currentTokens.AccessToken))
                    return false;

                var introspection = await _httpClient.IntrospectTokenAsync(
                    _currentTokens.AccessToken,
                    "access_token",
                    cancellationToken);

                return introspection.Active;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Refresh the current access token using the refresh token
        /// </summary>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Task representing the async operation</returns>
        public async Task RefreshTokensAsync(CancellationToken cancellationToken = default)
        {
            if (_currentTokens?.RefreshToken == null)
                throw new InvalidTokenException("No refresh token available");

            try
            {
#if NET6_0_OR_GREATER
                _logger?.LogDebug("Refreshing access token");
#endif

                // First validate the refresh token using introspection
                var refreshTokenValidation = await _httpClient.IntrospectTokenAsync(
                    _currentTokens.RefreshToken,
                    "refresh_token",
                    cancellationToken);

                if (!refreshTokenValidation.Active)
                {
#if NET6_0_OR_GREATER
                    _logger?.LogWarning("Refresh token is not active");
#endif
                    await LogoutAsync(false, cancellationToken);
                    throw new InvalidTokenException("Refresh token is not active");
                }

                var newTokens = await _httpClient.RefreshTokenAsync(_currentTokens.RefreshToken, cancellationToken);

                // Preserve refresh token if not provided in response
                if (string.IsNullOrEmpty(newTokens.RefreshToken))
                {
                    newTokens.RefreshToken = _currentTokens.RefreshToken;
                }

                await StoreTokensAsync(newTokens);

#if NET6_0_OR_GREATER
                _logger?.LogDebug("Access token refreshed successfully");
#endif
            }
            catch (Exception ex)
            {
#if NET6_0_OR_GREATER
                _logger?.LogError(ex, "Error refreshing tokens");
#endif

                // If refresh fails, log out the user
                await LogoutAsync(false, cancellationToken);
                throw new InvalidTokenException($"Token refresh failed: {ex.Message}");
            }
        }

        /// <summary>
        /// Log out the current user
        /// </summary>
        /// <param name="revokeTokens">Whether to call the server logout endpoint (deprecated parameter, always calls logout)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Task representing the async operation</returns>
        public async Task LogoutAsync(bool revokeTokens = true, CancellationToken cancellationToken = default)
        {
            try
            {
#if NET6_0_OR_GREATER
                _logger?.LogDebug("Logging out user");
#endif

                // Call logout endpoint on server if we have a session
                try
                {
                    await _httpClient.LogoutAsync(cancellationToken);
                }
                catch (Exception ex)
                {
#if NET6_0_OR_GREATER
                    _logger?.LogWarning(ex, "Failed to call logout endpoint on server, continuing with local logout");
#endif
                    // Continue with local logout even if server logout fails
                }

                // Clear local data
                await _storage.ClearAuthDataAsync(_storageKeyPrefix);
                _currentUser = null;
                _currentTokens = null;

                UpdateState(AuthState.Unauthenticated);

#if NET6_0_OR_GREATER
                _logger?.LogInformation("User logged out successfully");
#endif
            }
            catch (Exception ex)
            {
#if NET6_0_OR_GREATER
                _logger?.LogError(ex, "Error during logout");
#endif
                throw;
            }
        }

        /// <summary>
        /// Get the logout URL for redirecting the user's browser
        /// </summary>
        /// <param name="returnTo">URL to redirect to after logout</param>
        /// <returns>Logout URL</returns>
        public string GetLogoutUrl(string? returnTo = null)
        {
            return OAuthUtils.BuildLogoutUrl(_config, returnTo);
        }

        /// <summary>
        /// Check if the user has a specific role
        /// </summary>
        /// <param name="role">Role to check</param>
        /// <returns>True if user has the role</returns>
        public bool HasRole(string role)
        {
            return _currentUser?.HasRole(role) ?? false;
        }

        /// <summary>
        /// Check if the user has any of the specified roles
        /// </summary>
        /// <param name="roles">Roles to check</param>
        /// <returns>True if user has any of the roles</returns>
        public bool HasAnyRole(params string[] roles)
        {
            return _currentUser?.HasAnyRole(roles) ?? false;
        }

        /// <summary>
        /// Check if the user has all of the specified roles
        /// </summary>
        /// <param name="roles">Roles to check</param>
        /// <returns>True if user has all of the roles</returns>
        public bool HasAllRoles(params string[] roles)
        {
            return _currentUser?.HasAllRoles(roles) ?? false;
        }

        /// <summary>
        /// Get current user from cache (no server validation)
        /// Use this for UI updates where you don't need fresh data
        /// </summary>
        /// <returns>Cached user or null</returns>
        public BlitzWareUser? GetUserFromCache()
        {
            return _currentUser;
        }

        /// <summary>
        /// Refresh user information from the server
        /// </summary>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Task representing the async operation</returns>
        public async Task<BlitzWareUser?> RefreshUserAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                var accessToken = await GetAccessTokenAsync(cancellationToken);
                if (accessToken == null)
                    return null;

                await LoadUserInfoAsync(cancellationToken);
                return _currentUser;
            }
            catch (Exception ex)
            {
#if NET6_0_OR_GREATER
                _logger?.LogError(ex, "Error refreshing user info");
#endif
                return null;
            }
        }

        /// <summary>
        /// Validate and potentially refresh stored tokens
        /// </summary>
        /// <param name="tokens">Tokens to validate</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>True if tokens are valid</returns>
        private async Task<bool> ValidateAndRefreshTokensAsync(TokenResponse tokens, CancellationToken cancellationToken)
        {
            try
            {
                // Check if access token is expired locally
                if (tokens.IsExpired)
                {
                    if (!string.IsNullOrEmpty(tokens.RefreshToken))
                    {
                        // Try to refresh
                        try
                        {
                            var newTokens = await _httpClient.RefreshTokenAsync(tokens.RefreshToken, cancellationToken);
                            await StoreTokensAsync(newTokens);
                            return true;
                        }
                        catch
                        {
                            return false;
                        }
                    }
                    return false;
                }

                // Validate token with server using introspection
                var introspection = await _httpClient.IntrospectTokenAsync(tokens.AccessToken, "access_token", cancellationToken);
                if (introspection.Active)
                {
                    _currentTokens = tokens;
                    return true;
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Load user information using the current access token
        /// </summary>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Task representing the async operation</returns>
        private async Task LoadUserInfoAsync(CancellationToken cancellationToken)
        {
            if (_currentTokens?.AccessToken == null)
                throw new InvalidTokenException("No access token available");

            _currentUser = await _httpClient.GetUserInfoAsync(_currentTokens.AccessToken, cancellationToken);
            await _storage.StoreUserAsync(_currentUser, _storageKeyPrefix);
        }

        /// <summary>
        /// Store tokens securely
        /// </summary>
        /// <param name="tokens">Tokens to store</param>
        /// <returns>Task representing the async operation</returns>
        private async Task StoreTokensAsync(TokenResponse tokens)
        {
            _currentTokens = tokens;
            await _storage.StoreTokenResponseAsync(tokens, _storageKeyPrefix);
        }

        /// <summary>
        /// Clean up temporary authentication data
        /// </summary>
        /// <returns>Task representing the async operation</returns>
        private async Task CleanupAuthDataAsync()
        {
            var keysToClean = new[]
            {
                $"{_storageKeyPrefix}{StorageKeys.PKCECodeVerifier}",
                $"{_storageKeyPrefix}{StorageKeys.AuthState}",
                $"{_storageKeyPrefix}{StorageKeys.AuthNonce}"
            };

            foreach (var key in keysToClean)
            {
                await _storage.RemoveAsync(key);
            }
        }

        /// <summary>
        /// Update authentication state and fire event
        /// </summary>
        /// <param name="newState">New authentication state</param>
        /// <param name="user">Current user (optional)</param>
        /// <param name="error">Error that occurred (optional)</param>
        private void UpdateState(AuthState newState, BlitzWareUser? user = null, Exception? error = null)
        {
            var oldState = _currentState;
            _currentState = newState;

            if (newState != oldState)
            {
#if NET6_0_OR_GREATER
                _logger?.LogDebug("Auth state changed from {OldState} to {NewState}", oldState, newState);
#endif

                AuthStateChanged?.Invoke(this, new AuthStateChangedEventArgs(newState, user, error));
            }
        }

        /// <summary>
        /// Dispose resources
        /// </summary>
        public void Dispose()
        {
            _httpClient?.Dispose();
        }
    }
}