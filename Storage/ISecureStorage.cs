// BlitzWare .NET SDK - Secure Storage Interface
// Copyright (c) 2025 BlitzWare. All rights reserved.

using System;
using System.Threading.Tasks;
using BlitzWare.SDK.Models;

namespace BlitzWare.SDK.Storage
{
    /// <summary>
    /// Interface for secure storage of authentication tokens and user data
    /// </summary>
    public interface ISecureStorage
    {
        /// <summary>
        /// Store a value securely
        /// </summary>
        /// <param name="key">Storage key</param>
        /// <param name="value">Value to store</param>
        /// <returns>Task representing the async operation</returns>
        Task SetAsync(string key, string value);

        /// <summary>
        /// Retrieve a value securely
        /// </summary>
        /// <param name="key">Storage key</param>
        /// <returns>Stored value or null if not found</returns>
        Task<string?> GetAsync(string key);

        /// <summary>
        /// Remove a stored value
        /// </summary>
        /// <param name="key">Storage key</param>
        /// <returns>Task representing the async operation</returns>
        Task RemoveAsync(string key);

        /// <summary>
        /// Check if a key exists in storage
        /// </summary>
        /// <param name="key">Storage key</param>
        /// <returns>True if key exists</returns>
        Task<bool> ContainsKeyAsync(string key);

        /// <summary>
        /// Clear all stored values
        /// </summary>
        /// <returns>Task representing the async operation</returns>
        Task ClearAsync();

        /// <summary>
        /// Get the storage mechanism name (for debugging)
        /// </summary>
        string StorageType { get; }
    }

    /// <summary>
    /// Common storage keys used by the BlitzWare SDK
    /// </summary>
    public static class StorageKeys
    {
        public const string AccessToken = "blitzware_access_token";
        public const string RefreshToken = "blitzware_refresh_token";
        public const string IdToken = "blitzware_id_token";
        public const string TokenExpiry = "blitzware_token_expiry";
        public const string UserInfo = "blitzware_user_info";
        public const string LastAuthState = "blitzware_last_auth_state";
        public const string PKCECodeVerifier = "blitzware_pkce_verifier";
        public const string AuthState = "blitzware_auth_state";
        public const string AuthNonce = "blitzware_auth_nonce";

        /// <summary>
        /// Get a user-specific key
        /// </summary>
        /// <param name="baseKey">Base key</param>
        /// <param name="userId">User ID</param>
        /// <returns>User-specific key</returns>
        public static string GetUserKey(string baseKey, string userId)
        {
            return $"{baseKey}_{userId}";
        }

        /// <summary>
        /// Get a client-specific key
        /// </summary>
        /// <param name="baseKey">Base key</param>
        /// <param name="clientId">Client ID</param>
        /// <returns>Client-specific key</returns>
        public static string GetClientKey(string baseKey, string clientId)
        {
            return $"{baseKey}_{clientId}";
        }
    }

    /// <summary>
    /// Extension methods for secure storage
    /// </summary>
    public static class SecureStorageExtensions
    {
        /// <summary>
        /// Store a token response securely
        /// </summary>
        /// <param name="storage">Storage instance</param>
        /// <param name="tokenResponse">Token response to store</param>
        /// <param name="keyPrefix">Optional key prefix</param>
        /// <returns>Task representing the async operation</returns>
        public static async Task StoreTokenResponseAsync(this ISecureStorage storage, TokenResponse tokenResponse, string? keyPrefix = null)
        {
            if (storage == null) throw new ArgumentNullException(nameof(storage));
            if (tokenResponse == null) throw new ArgumentNullException(nameof(tokenResponse));

            var prefix = keyPrefix ?? string.Empty;

            await storage.SetAsync($"{prefix}{StorageKeys.AccessToken}", tokenResponse.AccessToken);
            
            if (!string.IsNullOrEmpty(tokenResponse.RefreshToken))
            {
                await storage.SetAsync($"{prefix}{StorageKeys.RefreshToken}", tokenResponse.RefreshToken);
            }
            
            if (!string.IsNullOrEmpty(tokenResponse.IdToken))
            {
                await storage.SetAsync($"{prefix}{StorageKeys.IdToken}", tokenResponse.IdToken);
            }

            await storage.SetAsync($"{prefix}{StorageKeys.TokenExpiry}", tokenResponse.ExpiryTime.ToBinary().ToString());
        }

        /// <summary>
        /// Retrieve a token response from storage
        /// </summary>
        /// <param name="storage">Storage instance</param>
        /// <param name="keyPrefix">Optional key prefix</param>
        /// <returns>Token response or null if not found</returns>
        public static async Task<TokenResponse?> GetTokenResponseAsync(this ISecureStorage storage, string? keyPrefix = null)
        {
            if (storage == null) throw new ArgumentNullException(nameof(storage));

            var prefix = keyPrefix ?? string.Empty;

            var accessToken = await storage.GetAsync($"{prefix}{StorageKeys.AccessToken}");
            if (string.IsNullOrEmpty(accessToken))
                return null;

            var refreshToken = await storage.GetAsync($"{prefix}{StorageKeys.RefreshToken}");
            var idToken = await storage.GetAsync($"{prefix}{StorageKeys.IdToken}");
            var expiryString = await storage.GetAsync($"{prefix}{StorageKeys.TokenExpiry}");

            var tokenResponse = new TokenResponse
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken,
                IdToken = idToken
            };

            if (!string.IsNullOrEmpty(expiryString) && long.TryParse(expiryString, out var expiryBinary))
            {
                try
                {
                    var expiryTime = DateTime.FromBinary(expiryBinary);
                    var secondsUntilExpiry = (long)(expiryTime - DateTime.UtcNow).TotalSeconds;
                    tokenResponse.ExpiresIn = Math.Max(0, secondsUntilExpiry);
                }
                catch
                {
                    // If parsing fails, assume token is expired
                    tokenResponse.ExpiresIn = 0;
                }
            }

            return tokenResponse;
        }

        /// <summary>
        /// Store user information securely
        /// </summary>
        /// <param name="storage">Storage instance</param>
        /// <param name="user">User information to store</param>
        /// <param name="keyPrefix">Optional key prefix</param>
        /// <returns>Task representing the async operation</returns>
        public static async Task StoreUserAsync(this ISecureStorage storage, BlitzWareUser user, string? keyPrefix = null)
        {
            if (storage == null) throw new ArgumentNullException(nameof(storage));
            if (user == null) throw new ArgumentNullException(nameof(user));

            var prefix = keyPrefix ?? string.Empty;
            var userJson = System.Text.Json.JsonSerializer.Serialize(user);
            await storage.SetAsync($"{prefix}{StorageKeys.UserInfo}", userJson);
        }

        /// <summary>
        /// Retrieve user information from storage
        /// </summary>
        /// <param name="storage">Storage instance</param>
        /// <param name="keyPrefix">Optional key prefix</param>
        /// <returns>User information or null if not found</returns>
        public static async Task<BlitzWareUser?> GetUserAsync(this ISecureStorage storage, string? keyPrefix = null)
        {
            if (storage == null) throw new ArgumentNullException(nameof(storage));

            var prefix = keyPrefix ?? string.Empty;
            var userJson = await storage.GetAsync($"{prefix}{StorageKeys.UserInfo}");
            
            if (string.IsNullOrEmpty(userJson))
                return null;

            try
            {
                return System.Text.Json.JsonSerializer.Deserialize<BlitzWareUser>(userJson);
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Clear all authentication data from storage
        /// </summary>
        /// <param name="storage">Storage instance</param>
        /// <param name="keyPrefix">Optional key prefix</param>
        /// <returns>Task representing the async operation</returns>
        public static async Task ClearAuthDataAsync(this ISecureStorage storage, string? keyPrefix = null)
        {
            if (storage == null) throw new ArgumentNullException(nameof(storage));

            var prefix = keyPrefix ?? string.Empty;
            var keys = new[]
            {
                $"{prefix}{StorageKeys.AccessToken}",
                $"{prefix}{StorageKeys.RefreshToken}",
                $"{prefix}{StorageKeys.IdToken}",
                $"{prefix}{StorageKeys.TokenExpiry}",
                $"{prefix}{StorageKeys.UserInfo}",
                $"{prefix}{StorageKeys.LastAuthState}",
                $"{prefix}{StorageKeys.PKCECodeVerifier}",
                $"{prefix}{StorageKeys.AuthState}",
                $"{prefix}{StorageKeys.AuthNonce}"
            };

            foreach (var key in keys)
            {
                await storage.RemoveAsync(key);
            }
        }

        /// <summary>
        /// Check if authentication data exists in storage
        /// </summary>
        /// <param name="storage">Storage instance</param>
        /// <param name="keyPrefix">Optional key prefix</param>
        /// <returns>True if authentication data exists</returns>
        public static async Task<bool> HasAuthDataAsync(this ISecureStorage storage, string? keyPrefix = null)
        {
            if (storage == null) throw new ArgumentNullException(nameof(storage));

            var prefix = keyPrefix ?? string.Empty;
            return await storage.ContainsKeyAsync($"{prefix}{StorageKeys.AccessToken}");
        }
    }
}