// BlitzWare .NET SDK - Console Application Example
// Copyright (c) 2025 BlitzWare. All rights reserved.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using BlitzWare.SDK;
using BlitzWare.SDK.Models;
using BlitzWare.SDK.Storage;

namespace BlitzWare.SDK.Examples.Console
{
    /// <summary>
    /// Example console application demonstrating BlitzWare .NET SDK usage
    /// </summary>
    class Program
    {
        private static BlitzWareAuth? _auth;

        static async Task Main(string[] args)
        {
            System.Console.WriteLine("BlitzWare .NET SDK - Console Example");
            System.Console.WriteLine("====================================");
            System.Console.WriteLine();

            try
            {
                // Initialize BlitzWare configuration
                var config = new BlitzWareConfig
                {
                    ClientId = GetConfigValue("BLITZWARE_CLIENT_ID", "2f465572-9a90-4bd1-b4ec-3b03b33fbb66"),
                    RedirectUri = GetConfigValue("BLITZWARE_REDIRECT_URI", "http://localhost:8080/callback"),
                    ResponseType = "code",
                    EnableLogging = true
                };

                // Validate configuration
                var validation = config.Validate();
                if (!validation.IsValid)
                {
                    System.Console.WriteLine("❌ Configuration errors:");
                    foreach (var error in validation.Errors)
                    {
                        System.Console.WriteLine($"   - {error}");
                    }
                    System.Console.WriteLine("\nPlease update the configuration above and try again.");
                    return;
                }

                // Use memory storage for this example (in production, use secure storage)
                var storage = new MemorySecureStorage();

                // Initialize BlitzWare auth
                _auth = new BlitzWareAuth(config, storage);

                // Subscribe to auth state changes
                _auth.AuthStateChanged += OnAuthStateChanged;

                // Initialize and check for existing session
                await _auth.InitializeAsync();

                if (_auth.IsAuthenticated)
                {
                    System.Console.WriteLine("✅ User is already authenticated!");
                    ShowUserInfo();
                }
                else
                {
                    System.Console.WriteLine("🔑 User is not authenticated. Starting login flow...");
                    await StartLoginFlow();
                }

                // Interactive menu
                await RunInteractiveMenu();
            }
            catch (Exception ex)
            {
                System.Console.WriteLine($"❌ Error: {ex.Message}");
                if (ex.InnerException != null)
                {
                    System.Console.WriteLine($"   Inner: {ex.InnerException.Message}");
                }
            }
            finally
            {
                _auth?.Dispose();
            }

            System.Console.WriteLine("\nPress any key to exit...");
            System.Console.ReadKey();
        }

        private static async Task StartLoginFlow()
        {
            try
            {
                System.Console.WriteLine("Starting OAuth login flow...");

                // Start the login flow
                var authRequest = await _auth!.StartLoginAsync();

                // Extract the port from the redirect URI
                var redirectUriStr = "http://localhost:8080/callback";
                if (authRequest.AuthorizationUrl.Contains("redirect_uri="))
                {
                    var parts = authRequest.AuthorizationUrl.Split(new[] { "redirect_uri=" }, StringSplitOptions.None);
                    if (parts.Length > 1)
                    {
                        var uriPart = parts[1].Split(new[] { '&' })[0];
                        redirectUriStr = Uri.UnescapeDataString(uriPart);
                    }
                }
                var redirectUri = new Uri(redirectUriStr);
                var port = redirectUri.Port;

                System.Console.WriteLine($"Starting local server on port {port}...");
                System.Console.WriteLine();

                // Start local HTTP listener to capture the callback
                using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(5)); // 5 minute timeout
                var callbackTask = StartHttpListenerAsync(port, cts.Token);

                // Open the authorization URL in the default browser
                System.Console.WriteLine("Opening browser for authentication...");
                OpenBrowser(authRequest.AuthorizationUrl);
                System.Console.WriteLine();
                System.Console.WriteLine("✓ Browser opened");
                System.Console.WriteLine("✓ Waiting for you to complete login in the browser...");
                System.Console.WriteLine("✓ You will be redirected automatically after login");
                System.Console.WriteLine();

                // Wait for the callback
                var callbackUrl = await callbackTask;

                if (string.IsNullOrWhiteSpace(callbackUrl))
                {
                    System.Console.WriteLine("❌ No callback received. Login cancelled or timed out.");
                    return;
                }

                // Handle the callback
                System.Console.WriteLine("Processing authentication...");
                await _auth.HandleCallbackAsync(callbackUrl);
            }
            catch (OperationCanceledException)
            {
                System.Console.WriteLine("❌ Login timed out after 5 minutes.");
            }
            catch (Exception ex)
            {
                System.Console.WriteLine($"❌ Login failed: {ex.Message}");
            }
        }

        private static async Task<string> StartHttpListenerAsync(int port, CancellationToken cancellationToken)
        {
            var listener = new HttpListener();
            listener.Prefixes.Add($"http://localhost:{port}/");

            try
            {
                listener.Start();
                System.Console.WriteLine($"✓ Local server listening on http://localhost:{port}/");
                System.Console.WriteLine();

                // Wait for incoming request
                var contextTask = listener.GetContextAsync();
                var completedTask = await Task.WhenAny(contextTask, Task.Delay(Timeout.Infinite, cancellationToken));

                if (completedTask != contextTask)
                {
                    // Timeout or cancellation
                    return string.Empty;
                }

                var context = await contextTask;
                var request = context.Request;
                var response = context.Response;

                // Build the callback URL from the request
                var callbackUrl = request.Url?.ToString() ?? string.Empty;

                // Send a response to the browser
                var responseString = @"
<!DOCTYPE html>
<html>
<head>
    <title>Authentication Complete</title>
</head>
<body>
    <div>
        <p>You have been successfully authenticated.</p>
        <p>You can close this window and return to the application.</p>
    </div>
</body>
</html>";

                var buffer = Encoding.UTF8.GetBytes(responseString);
                response.ContentLength64 = buffer.Length;
                response.ContentType = "text/html";
                response.StatusCode = 200;

                await response.OutputStream.WriteAsync(buffer, 0, buffer.Length, cancellationToken);
                response.OutputStream.Close();

                return callbackUrl;
            }
            catch (Exception ex)
            {
                System.Console.WriteLine($"❌ HTTP listener error: {ex.Message}");
                return string.Empty;
            }
            finally
            {
                listener.Stop();
                listener.Close();
            }
        }

        private static async Task RunInteractiveMenu()
        {
            while (true)
            {
                System.Console.WriteLine();
                System.Console.WriteLine("Available commands:");
                System.Console.WriteLine("1. Show user info");
                System.Console.WriteLine("2. Check roles");
                System.Console.WriteLine("3. Get access token");
                System.Console.WriteLine("4. Refresh token");
                System.Console.WriteLine("5. Login");
                System.Console.WriteLine("6. Logout");
                System.Console.WriteLine("7. Exit");
                System.Console.WriteLine();
                System.Console.Write("Enter command (1-7): ");

                var input = System.Console.ReadLine();
                System.Console.WriteLine();

                switch (input)
                {
                    case "1":
                        ShowUserInfo();
                        break;
                    case "2":
                        CheckRoles();
                        break;
                    case "3":
                        await ShowAccessToken();
                        break;
                    case "4":
                        await RefreshToken();
                        break;
                    case "5":
                        if (!_auth!.IsAuthenticated)
                        {
                            await StartLoginFlow();
                        }
                        else
                        {
                            System.Console.WriteLine("✅ Already authenticated!");
                        }
                        break;
                    case "6":
                        await Logout();
                        break;
                    case "7":
                        return;
                    default:
                        System.Console.WriteLine("❌ Invalid command. Please enter 1-7.");
                        break;
                }
            }
        }

        private static void ShowUserInfo()
        {
            if (!_auth!.IsAuthenticated)
            {
                System.Console.WriteLine("❌ User is not authenticated.");
                return;
            }

            var user = _auth.User!;
            System.Console.WriteLine("👤 User Information:");
            System.Console.WriteLine($"   ID: {user.Id}");
            System.Console.WriteLine($"   Username: {user.Username}");
            System.Console.WriteLine($"   Email: {user.Email}");
            System.Console.WriteLine($"   Display Name: {user.DisplayName}");
            System.Console.WriteLine($"   Initials: {user.Initials}");

            if (user.Roles.Count > 0)
            {
                System.Console.WriteLine($"   Roles: {string.Join(", ", user.Roles)}");
            }
            else
            {
                System.Console.WriteLine("   Roles: None");
            }
        }

        private static void CheckRoles()
        {
            if (!_auth!.IsAuthenticated)
            {
                System.Console.WriteLine("❌ User is not authenticated.");
                return;
            }

            System.Console.WriteLine("🔐 Role Checks:");
            System.Console.WriteLine($"   Is Admin: {_auth.HasRole("admin")}");
            System.Console.WriteLine($"   Is Moderator: {_auth.HasRole("moderator")}");
            System.Console.WriteLine($"   Is User: {_auth.HasRole("user")}");
            System.Console.WriteLine($"   Has Admin OR Moderator: {_auth.HasAnyRole("admin", "moderator")}");
            System.Console.WriteLine($"   Has Admin AND User: {_auth.HasAllRoles("admin", "user")}");
        }

        private static async Task ShowAccessToken()
        {
            if (!_auth!.IsAuthenticated)
            {
                System.Console.WriteLine("❌ User is not authenticated.");
                return;
            }

            try
            {
                var token = await _auth.GetAccessTokenAsync();
                if (token != null)
                {
                    System.Console.WriteLine("🔑 Access Token:");
                    System.Console.WriteLine($"   {token.Substring(0, Math.Min(20, token.Length))}... (truncated for security)");
                    System.Console.WriteLine($"   Length: {token.Length} characters");
                }
                else
                {
                    System.Console.WriteLine("❌ Failed to get access token.");
                }
            }
            catch (Exception ex)
            {
                System.Console.WriteLine($"❌ Error getting access token: {ex.Message}");
            }
        }

        private static async Task RefreshToken()
        {
            if (!_auth!.IsAuthenticated)
            {
                System.Console.WriteLine("❌ User is not authenticated.");
                return;
            }

            try
            {
                System.Console.WriteLine("🔄 Refreshing token...");
                await _auth.RefreshTokensAsync();
                System.Console.WriteLine("✅ Token refreshed successfully!");
            }
            catch (Exception ex)
            {
                System.Console.WriteLine($"❌ Error refreshing token: {ex.Message}");
            }
        }

        private static async Task Logout()
        {
            if (!_auth!.IsAuthenticated)
            {
                System.Console.WriteLine("❌ User is not authenticated.");
                return;
            }

            try
            {
                System.Console.WriteLine("👋 Logging out...");
                await _auth.LogoutAsync();
                System.Console.WriteLine("✅ Logged out successfully!");
            }
            catch (Exception ex)
            {
                System.Console.WriteLine($"❌ Error during logout: {ex.Message}");
            }
        }

        private static void OnAuthStateChanged(object? sender, AuthStateChangedEventArgs e)
        {
            System.Console.WriteLine();
            System.Console.WriteLine($"🔄 Auth state changed to: {e.State}");

            switch (e.State)
            {
                case AuthState.Authenticated:
                    System.Console.WriteLine($"✅ User {e.User?.DisplayName} is now authenticated!");
                    break;
                case AuthState.Unauthenticated:
                    System.Console.WriteLine("❌ User is no longer authenticated.");
                    break;
                case AuthState.Error:
                    System.Console.WriteLine($"💥 Authentication error: {e.Error?.Message}");
                    break;
                case AuthState.Loading:
                    System.Console.WriteLine("⏳ Loading authentication state...");
                    break;
            }
            System.Console.WriteLine();
        }

        private static string GetConfigValue(string envVar, string defaultValue)
        {
            return Environment.GetEnvironmentVariable(envVar) ?? defaultValue;
        }

        private static void OpenBrowser(string url)
        {
            try
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                {
                    Process.Start("xdg-open", url);
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                {
                    Process.Start("open", url);
                }
                else
                {
                    System.Console.WriteLine($"Please open this URL manually: {url}");
                }
            }
            catch
            {
                System.Console.WriteLine($"Could not open browser automatically. Please open this URL manually: {url}");
            }
        }
    }
}