// BlitzWare .NET SDK - Core Types and Models
// Copyright (c) 2025 BlitzWare. All rights reserved.

using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text.Json.Serialization;

namespace BlitzWare.SDK.Models
{
    /// <summary>
    /// Represents a BlitzWare user with authentication and role information
    /// </summary>
    public class BlitzWareUser
    {
        /// <summary>
        /// Unique user identifier
        /// </summary>
        [JsonPropertyName("id")]
        public string Id { get; set; } = string.Empty;

        /// <summary>
        /// User's username
        /// </summary>
        [JsonPropertyName("username")]
        public string Username { get; set; } = string.Empty;

        /// <summary>
        /// User's email address
        /// </summary>
        [JsonPropertyName("email")]
        public string Email { get; set; } = string.Empty;

        /// <summary>
        /// List of user roles for role-based access control (RBAC)
        /// </summary>
        [JsonPropertyName("roles")]
        public List<string> Roles { get; set; } = new List<string>();

        /// <summary>
        /// Additional properties that may be returned by the server
        /// </summary>
        [JsonExtensionData]
        public Dictionary<string, object>? AdditionalProperties { get; set; }

        /// <summary>
        /// Check if user has a specific role
        /// </summary>
        /// <param name="role">Role to check</param>
        /// <returns>True if user has the role</returns>
        public bool HasRole(string role)
        {
            return Roles?.Contains(role, StringComparer.OrdinalIgnoreCase) ?? false;
        }

        /// <summary>
        /// Check if user has any of the specified roles
        /// </summary>
        /// <param name="roles">Roles to check</param>
        /// <returns>True if user has any of the roles</returns>
        public bool HasAnyRole(params string[] roles)
        {
            return roles?.Any(HasRole) ?? false;
        }

        /// <summary>
        /// Check if user has any of the specified roles
        /// </summary>
        /// <param name="roles">Roles to check</param>
        /// <returns>True if user has any of the roles</returns>
        public bool HasAnyRole(IEnumerable<string> roles)
        {
            return roles?.Any(HasRole) ?? false;
        }

        /// <summary>
        /// Check if user has all of the specified roles
        /// </summary>
        /// <param name="roles">Roles to check</param>
        /// <returns>True if user has all of the roles</returns>
        public bool HasAllRoles(params string[] roles)
        {
            return roles?.All(HasRole) ?? false;
        }

        /// <summary>
        /// Check if user has all of the specified roles
        /// </summary>
        /// <param name="roles">Roles to check</param>
        /// <returns>True if user has all of the roles</returns>
        public bool HasAllRoles(IEnumerable<string> roles)
        {
            return roles?.All(HasRole) ?? false;
        }

        /// <summary>
        /// Check if user is an admin (has "admin" role)
        /// </summary>
        [JsonIgnore]
        public bool IsAdmin => HasRole("admin");

        /// <summary>
        /// Get display name for the user (prefers username, falls back to email)
        /// </summary>
        [JsonIgnore]
        public string DisplayName
        {
            get
            {
                if (!string.IsNullOrWhiteSpace(Username)) return Username;
                return Email;
            }
        }

        /// <summary>
        /// Get user initials for avatar fallback
        /// </summary>
        [JsonIgnore]
        public string Initials
        {
            get
            {
                var name = DisplayName;
                if (string.IsNullOrWhiteSpace(name)) return "?";
                
                var parts = name.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 2)
                {
                    return $"{parts[0][0]}{parts[parts.Length - 1][0]}".ToUpper();
                }
                else if (parts.Length == 1)
                {
                    return parts[0][0].ToString().ToUpper();
                }
                else
                {
                    return "?";
                }
            }
        }
    }

    /// <summary>
    /// Configuration for BlitzWare authentication
    /// </summary>
    public class BlitzWareConfig
    {
        /// <summary>
        /// Your BlitzWare client ID
        /// </summary>
        [Required]
        public string ClientId { get; set; } = string.Empty;

        /// <summary>
        /// Redirect URI for OAuth flow
        /// </summary>
        [Required]
        public string RedirectUri { get; set; } = string.Empty;

        /// <summary>
        /// OAuth response type ("code" or "token", "code" is recommended)
        /// </summary>
        public string ResponseType { get; set; } = "code";

        /// <summary>
        /// Additional OAuth parameters to include in authorization request
        /// </summary>
        public Dictionary<string, string> AdditionalParameters { get; set; } = new Dictionary<string, string>();

        /// <summary>
        /// Request timeout in milliseconds (default: 30000)
        /// </summary>
        public int TimeoutMs { get; set; } = 30000;

        /// <summary>
        /// User agent string for HTTP requests
        /// </summary>
        public string UserAgent { get; set; } = "BlitzWare-DotNet-SDK/1.0";

        /// <summary>
        /// Enable detailed logging (useful for debugging)
        /// </summary>
        public bool EnableLogging { get; set; } = false;

        /// <summary>
        /// Get the authorization URL for the OAuth flow
        /// </summary>
        [JsonIgnore]
        public string AuthorizationUrl => "https://auth.blitzware.xyz/api/auth/authorize";

        /// <summary>
        /// Get the token exchange URL
        /// </summary>
        [JsonIgnore]
        public string TokenUrl => "https://auth.blitzware.xyz/api/auth/token";

        /// <summary>
        /// Get the user info URL
        /// </summary>
        [JsonIgnore]
        public string UserInfoUrl => "https://auth.blitzware.xyz/api/auth/userinfo";

        /// <summary>
        /// Get the logout URL
        /// </summary>
        [JsonIgnore]
        public string LogoutUrl => "https://auth.blitzware.xyz/api/auth/logout";

        /// <summary>
        /// Validate the configuration
        /// </summary>
        /// <returns>Validation result</returns>
        public ValidationResult Validate()
        {
            var errors = new List<string>();

            if (string.IsNullOrWhiteSpace(ClientId))
                errors.Add("Client ID cannot be empty");

            if (string.IsNullOrWhiteSpace(RedirectUri))
                errors.Add("Redirect URI cannot be empty");

            if (!Uri.TryCreate(RedirectUri, UriKind.Absolute, out _))
                errors.Add("Redirect URI must be a valid absolute URI");

            if (ResponseType != "code" && ResponseType != "token")
                errors.Add("Response type must be 'code' or 'token'");

            return new ValidationResult(errors);
        }
    }

    /// <summary>
    /// Validation result for configuration
    /// </summary>
    public class ValidationResult
    {
        public bool IsValid => !Errors.Any();
        public List<string> Errors { get; }

        public ValidationResult(List<string> errors)
        {
            Errors = errors ?? new List<string>();
        }

        public static ValidationResult Success() => new(new List<string>());
    }

    /// <summary>
    /// OAuth token response
    /// Note: ID tokens are not supported by BlitzWare OAuth 2.0 service
    /// </summary>
    public class TokenResponse
    {
        [JsonPropertyName("access_token")]
        public string AccessToken { get; set; } = string.Empty;

        /// <summary>
        /// Note: ID tokens are not currently supported by BlitzWare OAuth 2.0 service
        /// </summary>
        [JsonPropertyName("id_token")]
        public string? IdToken { get; set; }

        [JsonPropertyName("refresh_token")]
        public string? RefreshToken { get; set; }

        [JsonPropertyName("token_type")]
        public string TokenType { get; set; } = "Bearer";

        [JsonPropertyName("expires_in")]
        public long ExpiresIn { get; set; } = 3600;

        [JsonPropertyName("scope")]
        public string? Scope { get; set; }

        /// <summary>
        /// Calculate token expiry time
        /// </summary>
        [JsonIgnore]
        public DateTime ExpiryTime => DateTime.UtcNow.AddSeconds(ExpiresIn);

        /// <summary>
        /// Check if token is expired
        /// </summary>
        [JsonIgnore]
        public bool IsExpired => DateTime.UtcNow >= ExpiryTime;

        /// <summary>
        /// Check if token will expire soon (within 5 minutes)
        /// </summary>
        [JsonIgnore]
        public bool WillExpireSoon => DateTime.UtcNow >= ExpiryTime.AddMinutes(-5);
    }

    /// <summary>
    /// Authentication state
    /// </summary>
    public enum AuthState
    {
        Loading,
        Unauthenticated,
        Authenticated,
        Error
    }

    /// <summary>
    /// Authentication state change event arguments
    /// </summary>
    public class AuthStateChangedEventArgs : EventArgs
    {
        public AuthState State { get; }
        public BlitzWareUser? User { get; }
        public Exception? Error { get; }

        public AuthStateChangedEventArgs(AuthState state, BlitzWareUser? user = null, Exception? error = null)
        {
            State = state;
            User = user;
            Error = error;
        }
    }

    /// <summary>
    /// BlitzWare SDK exceptions
    /// </summary>
    public abstract class BlitzWareException : Exception
    {
        protected BlitzWareException(string message) : base(message) { }
        protected BlitzWareException(string message, Exception innerException) : base(message, innerException) { }
    }

    /// <summary>
    /// Authentication failed exception
    /// </summary>
    public class AuthenticationFailedException : BlitzWareException
    {
        public string Reason { get; }

        public AuthenticationFailedException(string reason) : base($"Authentication failed: {reason}")
        {
            Reason = reason;
        }

        public AuthenticationFailedException(string reason, Exception innerException) 
            : base($"Authentication failed: {reason}", innerException)
        {
            Reason = reason;
        }
    }

    /// <summary>
    /// Network error exception
    /// </summary>
    public class NetworkException : BlitzWareException
    {
        public NetworkException(string message) : base($"Network error: {message}") { }
        public NetworkException(string message, Exception innerException) : base($"Network error: {message}", innerException) { }
    }

    /// <summary>
    /// Invalid token exception
    /// </summary>
    public class InvalidTokenException : BlitzWareException
    {
        public InvalidTokenException() : base("Invalid or expired token") { }
        public InvalidTokenException(string message) : base(message) { }
    }

    /// <summary>
    /// User info retrieval failed exception
    /// </summary>
    public class UserInfoException : BlitzWareException
    {
        public UserInfoException() : base("Failed to retrieve user information") { }
        public UserInfoException(string message) : base(message) { }
        public UserInfoException(string message, Exception innerException) : base(message, innerException) { }
    }

    /// <summary>
    /// Storage error exception
    /// </summary>
    public class StorageException : BlitzWareException
    {
        public StorageException(string message) : base($"Storage error: {message}") { }
        public StorageException(string message, Exception innerException) : base($"Storage error: {message}", innerException) { }
    }

    /// <summary>
    /// Configuration error exception
    /// </summary>
    public class ConfigurationException : BlitzWareException
    {
        public ConfigurationException(string message) : base($"Configuration error: {message}") { }
    }

    /// <summary>
    /// PKCE (Proof Key for Code Exchange) data
    /// </summary>
    public class PKCEData
    {
        public string CodeVerifier { get; set; } = string.Empty;
        public string CodeChallenge { get; set; } = string.Empty;
        public string CodeChallengeMethod { get; set; } = "S256";
    }

    /// <summary>
    /// Authentication request data
    /// </summary>
    public class AuthRequest
    {
        public string AuthorizationUrl { get; set; } = string.Empty;
        public PKCEData PKCEData { get; set; } = new();
        public string State { get; set; } = string.Empty;
        public string? Nonce { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Check if the auth request has expired (default: 10 minutes)
        /// </summary>
        public bool IsExpired(TimeSpan? timeout = null)
        {
            var timeoutSpan = timeout ?? TimeSpan.FromMinutes(10);
            return DateTime.UtcNow - CreatedAt > timeoutSpan;
        }
    }

    /// <summary>
    /// Authorization response from OAuth provider
    /// </summary>
    public class AuthorizationResponse
    {
        public bool IsSuccess { get; set; }
        public string? Code { get; set; }
        public string? State { get; set; }
        public string? Error { get; set; }
        public string? ErrorDescription { get; set; }
    }

    /// <summary>
    /// Token refresh request
    /// </summary>
    public class RefreshTokenRequest
    {
        [JsonPropertyName("grant_type")]
        public string GrantType { get; set; } = "refresh_token";

        [JsonPropertyName("client_id")]
        public string ClientId { get; set; } = string.Empty;

        [JsonPropertyName("refresh_token")]
        public string RefreshToken { get; set; } = string.Empty;
    }

    /// <summary>
    /// Authorization code exchange request
    /// </summary>
    public class TokenExchangeRequest
    {
        [JsonPropertyName("grant_type")]
        public string GrantType { get; set; } = "authorization_code";

        [JsonPropertyName("client_id")]
        public string ClientId { get; set; } = string.Empty;

        [JsonPropertyName("code")]
        public string Code { get; set; } = string.Empty;

        [JsonPropertyName("redirect_uri")]
        public string RedirectUri { get; set; } = string.Empty;

        [JsonPropertyName("code_verifier")]
        public string CodeVerifier { get; set; } = string.Empty;
    }

    /// <summary>
    /// Token introspection response (RFC 7662 OAuth2 Token Introspection)
    /// </summary>
    public class TokenIntrospectionResponse
    {
        /// <summary>
        /// Whether the token is currently active
        /// </summary>
        [JsonPropertyName("active")]
        public bool Active { get; set; }

        /// <summary>
        /// Client identifier for the OAuth 2.0 client
        /// </summary>
        [JsonPropertyName("client_id")]
        public string? ClientId { get; set; }

        /// <summary>
        /// Human-readable identifier for the resource owner
        /// </summary>
        [JsonPropertyName("username")]
        public string? Username { get; set; }

        /// <summary>
        /// Scope values for the token
        /// </summary>
        [JsonPropertyName("scope")]
        public string? Scope { get; set; }

        /// <summary>
        /// Subject of the token (usually user ID)
        /// </summary>
        [JsonPropertyName("sub")]
        public string? Sub { get; set; }

        /// <summary>
        /// Intended audience for the token
        /// </summary>
        [JsonPropertyName("aud")]
        public string? Aud { get; set; }

        /// <summary>
        /// Issuer of the token
        /// </summary>
        [JsonPropertyName("iss")]
        public string? Iss { get; set; }

        /// <summary>
        /// Expiration time (seconds since Unix epoch)
        /// </summary>
        [JsonPropertyName("exp")]
        public long? Exp { get; set; }

        /// <summary>
        /// Issued at time (seconds since Unix epoch)
        /// </summary>
        [JsonPropertyName("iat")]
        public long? Iat { get; set; }

        /// <summary>
        /// Token type (e.g., "Bearer")
        /// </summary>
        [JsonPropertyName("token_type")]
        public string? TokenType { get; set; }

        /// <summary>
        /// Additional properties that may be returned
        /// </summary>
        [JsonExtensionData]
        public Dictionary<string, object>? AdditionalProperties { get; set; }
    }

    /// <summary>
    /// Common OAuth scopes
    /// </summary>
    public static class BlitzWareScopes
    {
        public const string OpenId = "openid";
        public const string Profile = "profile";
        public const string Email = "email";
        public const string Roles = "roles";
        public const string OfflineAccess = "offline_access";

        /// <summary>
        /// Standard scopes for most applications
        /// </summary>
        public static readonly List<string> Standard = new() { OpenId, Profile, Email, Roles };

        /// <summary>
        /// Standard scopes with offline access (refresh tokens)
        /// </summary>
        public static readonly List<string> WithRefresh = new() { OpenId, Profile, Email, Roles, OfflineAccess };
    }
}