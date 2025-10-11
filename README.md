# .NET# BlitzWare .NET SDK



This guide demonstrates how to add user authentication to a .NET application using BlitzWare.A comprehensive .NET SDK for BlitzWare authentication that works across all .NET platforms including Console Applications, WinForms, WPF, UWP, MAUI, ASP.NET, Unity, and more.



This tutorial is based on the [Console example app](https://github.com/LanderDK/blitzware-dotnet-sdk/tree/master/Examples/Console).## 🚀 Features



1. [Configure BlitzWare](#1-configure-blitzware)- **Universal Compatibility**: Works with .NET Standard 2.0, .NET 6.0, and .NET 8.0

2. [Install the BlitzWare .NET SDK](#2-install-the-blitzware-net-sdk)- **Cross-Platform**: Supports Windows, macOS, and Linux

3. [Implementation Guide](#3-implementation-guide)- **OAuth 2.0 with PKCE**: Secure authentication flow with Proof Key for Code Exchange

- **Secure Token Storage**: Platform-specific secure storage (Windows Credential Manager, Keychain, etc.)

---- **Role-Based Access Control**: Built-in support for user roles and permissions

- **Automatic Token Refresh**: Seamless token renewal without user intervention

## 1) Configure BlitzWare- **Multiple UI Frameworks**: Examples for Console, WinForms, WPF, MAUI, ASP.NET

- **Type-Safe**: Full TypeScript-like IntelliSense support with nullable reference types

### Get Your Application Keys- **Logging Support**: Built-in logging for debugging and monitoring

- **Offline Support**: Works with cached credentials when network is unavailable

You will need some details about your application to communicate with BlitzWare. You can get these details from the **Application Settings** section in the BlitzWare dashboard.

## 📦 Installation

**You need the Client ID.**

### Package Manager Console

### Configure Redirect URIs```powershell

Install-Package BlitzWare.SDK

A redirect URI is a URL in your application where BlitzWare redirects the user after they have authenticated. The redirect URI for your app must be added to the **Redirect URIs** list in your **Application Settings** under the **Security** tab. If this is not set, users will be unable to log in to the application and will get an error.```



For desktop/console applications, use a localhost redirect URI:### .NET CLI

``````bash

http://localhost:8080/callbackdotnet add package BlitzWare.SDK

``````



---### PackageReference

```xml

## 2) Install the BlitzWare .NET SDK<PackageReference Include="BlitzWare.SDK" Version="1.0.0" />

```

### Prerequisites

## 🎯 Quick Start

This SDK supports:

- **.NET Standard 2.0** and higher### 1. Basic Setup

- **.NET 6.0** and higher

- **.NET 8.0** and higher```csharp

- **Windows, macOS, and Linux**using BlitzWare.SDK;

using BlitzWare.SDK.Models;

The SDK works with Console Applications, WinForms, WPF, MAUI, ASP.NET Core, Unity, and more.using BlitzWare.SDK.Storage;



### Installation// Configure BlitzWare

var config = new BlitzWareConfig

Install via NuGet Package Manager:{

    ClientId = "your-client-id",

```bash    Domain = "your-domain.blitzware.com",

dotnet add package BlitzWare.SDK    RedirectUri = "http://localhost:8080/callback",

```    Scopes = BlitzWareScopes.WithRefresh // Includes refresh tokens

};

Or via Package Manager Console:

// Initialize authentication (uses platform-appropriate secure storage)

```powershellvar auth = new BlitzWareAuth(config);

Install-Package BlitzWare.SDK

```// Subscribe to auth state changes

auth.AuthStateChanged += (sender, e) =>

### Platform Setup{

    Console.WriteLine($"Auth state: {e.State}");

The SDK automatically selects the appropriate secure storage for your platform:    if (e.State == AuthState.Authenticated)

    {

- **Windows**: Windows Credential Manager        Console.WriteLine($"Welcome, {e.User?.DisplayName}!");

- **macOS**: Keychain (future support)    }

- **Linux**: Secret Service (future support)};

- **Development**: In-memory storage

// Initialize and check for existing session

---await auth.InitializeAsync();

```

## 3) Implementation Guide

### 2. Login Flow

Follow this step-by-step guide to implement authentication in your app.

```csharp

### Step 1: Configure the SDK// Start login flow

var authRequest = await auth.StartLoginAsync();

Create and configure the BlitzWare authentication client:

// Open browser to authorization URL

```csharpProcess.Start(new ProcessStartInfo(authRequest.AuthorizationUrl) 

using BlitzWare.SDK;{ 

using BlitzWare.SDK.Models;    UseShellExecute = true 

using BlitzWare.SDK.Storage;});



// BlitzWare configuration// Handle the callback (get this from your redirect URI)

var config = new BlitzWareConfigstring callbackUrl = "http://localhost:8080/callback?code=...&state=...";

{await auth.HandleCallbackAsync(callbackUrl);

    ClientId = "your-client-id",

    RedirectUri = "http://localhost:8080/callback",// User is now authenticated!

    ResponseType = "code", // OAuth 2.0 authorization code flowif (auth.IsAuthenticated)

    EnableLogging = true{

};    Console.WriteLine($"Hello, {auth.User?.Name}!");

}

// Create authentication client```

// For production, use secure storage (e.g., WindowsCredentialStorage)

// For development/testing, use MemorySecureStorage### 3. Working with User Data

var storage = new MemorySecureStorage();

var auth = new BlitzWareAuth(config, storage);```csharp

var user = auth.User;

// Subscribe to auth state changesif (user != null)

auth.AuthStateChanged += (sender, e) =>{

{    Console.WriteLine($"User ID: {user.Id}");

    Console.WriteLine($"Auth state changed: {e.State}");    Console.WriteLine($"Username: {user.Username}");

    if (e.State == AuthState.Authenticated)    Console.WriteLine($"Email: {user.Email}");

    {    Console.WriteLine($"Display Name: {user.DisplayName}");

        Console.WriteLine($"Welcome, {e.User?.DisplayName}!");    Console.WriteLine($"Roles: {string.Join(", ", user.Roles)}");

    }    

};    // Role-based access control

    if (user.HasRole("admin"))

// Initialize and check for existing session    {

await auth.InitializeAsync();        Console.WriteLine("User is an administrator");

```    }

    

### Step 2: Implement Login Flow    if (user.HasAnyRole("admin", "moderator"))

    {

The SDK uses OAuth 2.0 with PKCE (Proof Key for Code Exchange) for secure authentication. The login flow automatically opens the user's browser and captures the callback using a local HTTP listener.        Console.WriteLine("User has elevated privileges");

    }

```csharp}

using System.Diagnostics;```

using System.Net;

using System.Text;### 4. API Calls with Authentication



private static async Task LoginAsync(BlitzWareAuth auth)```csharp

{// Get access token (automatically refreshes if needed)

    tryvar accessToken = await auth.GetAccessTokenAsync();

    {

        Console.WriteLine("Starting OAuth login flow...");// Make authenticated API calls

using var httpClient = new HttpClient();

        // Start the login flowhttpClient.DefaultRequestHeaders.Authorization = 

        var authRequest = await auth.StartLoginAsync();    new AuthenticationHeaderValue("Bearer", accessToken);



        // Extract the port from redirect URIvar response = await httpClient.GetAsync("https://api.yourapp.com/protected-endpoint");

        var redirectUri = new Uri(auth.Config.RedirectUri);```

        var port = redirectUri.Port;

## 🖥️ Platform-Specific Examples

        Console.WriteLine($"Starting local server on port {port}...");

### Console Application

        // Start local HTTP listener to capture the callback

        using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(5));```csharp

        var callbackTask = StartHttpListenerAsync(port, cts.Token);class Program

{

        // Open the authorization URL in the default browser    static async Task Main(string[] args)

        Console.WriteLine("Opening browser for authentication...");    {

        OpenBrowser(authRequest.AuthorizationUrl);        var config = new BlitzWareConfig

                {

        Console.WriteLine("Waiting for you to complete login in the browser...");            ClientId = "your-client-id",

        Console.WriteLine("You will be redirected automatically after login.");            Domain = "your-domain.blitzware.com",

            RedirectUri = "http://localhost:8080/callback"

        // Wait for the callback        };

        var callbackUrl = await callbackTask;

        using var auth = new BlitzWareAuth(config);

        if (string.IsNullOrWhiteSpace(callbackUrl))        await auth.InitializeAsync();

        {

            Console.WriteLine("❌ No callback received. Login cancelled or timed out.");        if (!auth.IsAuthenticated)

            return;        {

        }            // Start login flow

            var authRequest = await auth.StartLoginAsync();

        // Handle the callback            

        Console.WriteLine("Processing authentication...");            // Open browser

        await auth.HandleCallbackAsync(callbackUrl);            Process.Start(new ProcessStartInfo(authRequest.AuthorizationUrl) 

                    { 

        Console.WriteLine("✅ Login successful!");                UseShellExecute = true 

    }            });

    catch (Exception ex)            

    {            // Wait for callback URL from user

        Console.WriteLine($"❌ Login failed: {ex.Message}");            Console.Write("Paste callback URL: ");

    }            var callbackUrl = Console.ReadLine();

}            

            await auth.HandleCallbackAsync(callbackUrl);

private static async Task<string> StartHttpListenerAsync(int port, CancellationToken cancellationToken)        }

{

    var listener = new HttpListener();        Console.WriteLine($"Welcome, {auth.User?.DisplayName}!");

    listener.Prefixes.Add($"http://localhost:{port}/");    }

}

    try```

    {

        listener.Start();### WinForms Application

        Console.WriteLine($"✓ Local server listening on http://localhost:{port}/");

```csharp

        // Wait for incoming requestpublic partial class MainForm : Form

        var contextTask = listener.GetContextAsync();{

        var completedTask = await Task.WhenAny(contextTask, Task.Delay(Timeout.Infinite, cancellationToken));    private BlitzWareAuth _auth;



        if (completedTask != contextTask)    public MainForm()

        {    {

            return string.Empty;        InitializeComponent();

        }        InitializeAuth();

    }

        var context = await contextTask;

        var callbackUrl = context.Request.Url?.ToString() ?? string.Empty;    private async void InitializeAuth()

    {

        // Send success response to browser        var config = new BlitzWareConfig

        var responseHtml = @"        {

<!DOCTYPE html>            ClientId = "your-client-id",

<html>            Domain = "your-domain.blitzware.com",

<head><title>Authentication Complete</title></head>            RedirectUri = "http://localhost:8080/callback"

<body>        };

    <h1>✅ Authentication Successful</h1>

    <p>You can close this window and return to the application.</p>        // Use Windows Credential Manager for secure storage

</body>        var storage = new WindowsCredentialStorage();

</html>";        _auth = new BlitzWareAuth(config, storage);

        

        var buffer = Encoding.UTF8.GetBytes(responseHtml);        _auth.AuthStateChanged += OnAuthStateChanged;

        context.Response.ContentLength64 = buffer.Length;        await _auth.InitializeAsync();

        context.Response.ContentType = "text/html";    }

        context.Response.StatusCode = 200;

    private void OnAuthStateChanged(object sender, AuthStateChangedEventArgs e)

        await context.Response.OutputStream.WriteAsync(buffer, 0, buffer.Length, cancellationToken);    {

        context.Response.OutputStream.Close();        // Update UI based on auth state

        Invoke(() =>

        return callbackUrl;        {

    }            loginButton.Enabled = e.State == AuthState.Unauthenticated;

    finally            logoutButton.Enabled = e.State == AuthState.Authenticated;

    {            

        listener.Stop();            if (e.State == AuthState.Authenticated)

        listener.Close();            {

    }                userLabel.Text = $"Welcome, {e.User?.DisplayName}!";

}            }

        });

private static void OpenBrowser(string url)    }

{

    try    private async void LoginButton_Click(object sender, EventArgs e)

    {    {

        Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });        var authRequest = await _auth.StartLoginAsync();

    }        

    catch        // Show login dialog with embedded browser

    {        using var loginDialog = new LoginDialog(authRequest.AuthorizationUrl);

        Console.WriteLine($"Please open this URL manually: {url}");        if (loginDialog.ShowDialog() == DialogResult.OK)

    }        {

}            await _auth.HandleCallbackAsync(loginDialog.CallbackUrl);

```        }

    }

### Step 3: Display User Information}

```

Access and display authenticated user information:

### ASP.NET Core

```csharp

private static void ShowUserInfo(BlitzWareAuth auth)```csharp

{// Startup.cs or Program.cs

    if (!auth.IsAuthenticated)services.AddSingleton<BlitzWareConfig>(provider =>

    {{

        Console.WriteLine("❌ User is not authenticated.");    return new BlitzWareConfig

        return;    {

    }        ClientId = Configuration["BlitzWare:ClientId"],

        Domain = Configuration["BlitzWare:Domain"],

    var user = auth.User!;        RedirectUri = Configuration["BlitzWare:RedirectUri"]

    Console.WriteLine("👤 User Information:");    };

    Console.WriteLine($"   ID: {user.Id}");});

    Console.WriteLine($"   Username: {user.Username}");

    Console.WriteLine($"   Email: {user.Email}");services.AddScoped<BlitzWareAuth>();

    Console.WriteLine($"   Display Name: {user.DisplayName}");

    Console.WriteLine($"   Initials: {user.Initials}");// Controller

[ApiController]

    if (user.Roles.Count > 0)[Route("api/[controller]")]

    {public class AuthController : ControllerBase

        Console.WriteLine($"   Roles: {string.Join(", ", user.Roles)}");{

    }    private readonly BlitzWareAuth _auth;

    else

    {    public AuthController(BlitzWareAuth auth)

        Console.WriteLine("   Roles: None");    {

    }        _auth = auth;

}    }

```

    [HttpGet("login")]

### Step 4: Access Token Management    public async Task<IActionResult> Login()

    {

Get access tokens for making authenticated API calls:        var authRequest = await _auth.StartLoginAsync();

        return Redirect(authRequest.AuthorizationUrl);

```csharp    }

using System.Net.Http;

using System.Net.Http.Headers;    [HttpGet("callback")]

    public async Task<IActionResult> Callback()

private static async Task MakeApiCallAsync(BlitzWareAuth auth)    {

{        var callbackUrl = Request.GetDisplayUrl();

    try        await _auth.HandleCallbackAsync(callbackUrl);

    {        

        // Get access token (automatically refreshes if needed)        return Ok(new { user = _auth.User });

        var token = await auth.GetAccessTokenAsync();    }

}

        if (token == null)```

        {

            Console.WriteLine("❌ No access token available");## 🔧 Configuration Options

            return;

        }```csharp

var config = new BlitzWareConfig

        // Make authenticated API call{

        using var httpClient = new HttpClient();    // Required

        httpClient.DefaultRequestHeaders.Authorization =     ClientId = "your-client-id",

            new AuthenticationHeaderValue("Bearer", token);    Domain = "your-domain.blitzware.com",

    RedirectUri = "your-redirect-uri",

        var response = await httpClient.GetAsync("https://api.yourservice.com/protected");    

    // Optional

        if (response.IsSuccessStatusCode)    Scopes = new List<string> { "openid", "profile", "email", "roles" },

        {    AdditionalParameters = new Dictionary<string, string>

            var content = await response.Content.ReadAsStringAsync();    {

            Console.WriteLine($"✅ API Response: {content}");        ["prompt"] = "login",

        }        ["max_age"] = "3600"

        else    },

        {    CustomScheme = "myapp", // For mobile/desktop apps

            Console.WriteLine($"❌ API Error: {response.StatusCode}");    EnableLogging = true,

        }    TimeoutMs = 30000,

    }    UserAgent = "MyApp/1.0.0"

    catch (Exception ex)};

    {```

        Console.WriteLine($"❌ Error making API call: {ex.Message}");

    }## 🔐 Secure Storage Options

}

```The SDK automatically chooses the best secure storage for your platform:



### Step 5: Role-Based Access Control- **Windows**: Credential Manager

- **macOS**: Keychain Services  

Implement role-based features using the built-in role checking methods:- **Linux**: Secret Service (libsecret)

- **Other**: Encrypted local storage

```csharp- **Development**: In-memory storage (for testing)

private static void CheckRoles(BlitzWareAuth auth)

{### Custom Storage

    if (!auth.IsAuthenticated)

    {```csharp

        Console.WriteLine("❌ User is not authenticated.");// Implement ISecureStorage for custom storage

        return;public class CustomSecureStorage : ISecureStorage

    }{

    public Task SetAsync(string key, string value) { /* ... */ }

    Console.WriteLine("🔐 Role Checks:");    public Task<string?> GetAsync(string key) { /* ... */ }

        public Task RemoveAsync(string key) { /* ... */ }

    // Check individual role    public Task<bool> ContainsKeyAsync(string key) { /* ... */ }

    Console.WriteLine($"   Is Admin: {auth.HasRole("admin")}");    public Task ClearAsync() { /* ... */ }

    Console.WriteLine($"   Is Moderator: {auth.HasRole("moderator")}");    public string StorageType => "Custom Storage";

    Console.WriteLine($"   Is User: {auth.HasRole("user")}");}

    

    // Check any role (OR logic)// Use custom storage

    Console.WriteLine($"   Has Admin OR Moderator: {auth.HasAnyRole("admin", "moderator")}");var auth = new BlitzWareAuth(config, new CustomSecureStorage());

    ```

    // Check all roles (AND logic)

    Console.WriteLine($"   Has Admin AND User: {auth.HasAllRoles("admin", "user")}");## 🎭 Role-Based Access Control



    // User object also has role checking```csharp

    var user = auth.User!;// Check individual roles

    Console.WriteLine($"   Is Admin (via user): {user.IsAdmin}");if (auth.HasRole("admin"))

}{

    // Admin-only functionality

// Example: Role-based UI}

private static void ShowDashboard(BlitzWareAuth auth)

{// Check multiple roles (OR)

    var user = auth.User!;if (auth.HasAnyRole("admin", "moderator"))

    {

    Console.WriteLine($"Welcome, {user.DisplayName}!");    // Elevated privileges required

    Console.WriteLine();}



    // Admin-only section// Check multiple roles (AND)

    if (auth.HasRole("admin"))if (auth.HasAllRoles("user", "premium"))

    {{

        Console.WriteLine("🔴 Admin Panel:");    // Premium user functionality

        Console.WriteLine("   - Manage Users");}

        Console.WriteLine("   - View System Logs");

        Console.WriteLine("   - Configure Settings");// User object methods

        Console.WriteLine();var user = auth.User;

    }Console.WriteLine($"Is Admin: {user.IsAdmin}");

Console.WriteLine($"Is Moderator: {user.IsModerator}");

    // Premium user sectionConsole.WriteLine($"Roles: {string.Join(", ", user.Roles)}");

    if (auth.HasRole("premium"))```

    {

        Console.WriteLine("⭐ Premium Features:");## 🔄 Token Management

        Console.WriteLine("   - Advanced Analytics");

        Console.WriteLine("   - Priority Support");```csharp

        Console.WriteLine("   - Custom Themes");// Get current access token (auto-refreshes if needed)

        Console.WriteLine();var token = await auth.GetAccessTokenAsync();

    }

// Manual token refresh

    // Regular user section (always visible)await auth.RefreshTokensAsync();

    Console.WriteLine("📊 Dashboard:");

    Console.WriteLine("   - View Profile");// Check token expiry

    Console.WriteLine("   - Update Settings");var tokens = await storage.GetTokenResponseAsync();

    Console.WriteLine("   - View History");if (tokens != null)

}{

```    Console.WriteLine($"Expires: {tokens.ExpiryTime}");

    Console.WriteLine($"Is Expired: {tokens.IsExpired}");

### Step 6: Token Refresh    Console.WriteLine($"Will Expire Soon: {tokens.WillExpireSoon}");

}

The SDK automatically refreshes tokens when needed, but you can also manually refresh:```



```csharp## 📱 Mobile & Desktop Integration

private static async Task RefreshTokenAsync(BlitzWareAuth auth)

{### Custom URL Schemes

    if (!auth.IsAuthenticated)

    {```csharp

        Console.WriteLine("❌ User is not authenticated.");var config = new BlitzWareConfig

        return;{

    }    ClientId = "your-client-id",

    Domain = "your-domain.blitzware.com",

    try    RedirectUri = "myapp://auth/callback", // Custom scheme

    {    CustomScheme = "myapp"

        Console.WriteLine("🔄 Refreshing token...");};

        await auth.RefreshTokensAsync();```

        Console.WriteLine("✅ Token refreshed successfully!");

    }### Deep Links

    catch (Exception ex)

    {```csharp

        Console.WriteLine($"❌ Error refreshing token: {ex.Message}");// Generate deep link for login

    }var deepLink = OAuthUtils.CreateDeepLink(

}    scheme: "myapp",

```    host: "auth", 

    action: "login",

### Step 7: Logout    parameters: new Dictionary<string, string>

    {

Log out the current user and clear stored tokens:        ["return_to"] = "/dashboard"

    }

```csharp);

private static async Task LogoutAsync(BlitzWareAuth auth)// Result: myapp://auth/login?return_to=%2Fdashboard

{```

    if (!auth.IsAuthenticated)

    {## 🐛 Error Handling

        Console.WriteLine("❌ User is not authenticated.");

        return;```csharp

    }try

{

    try    await auth.HandleCallbackAsync(callbackUrl);

    {}

        Console.WriteLine("👋 Logging out...");catch (AuthenticationFailedException ex)

        await auth.LogoutAsync();{

        Console.WriteLine("✅ Logged out successfully!");    Console.WriteLine($"Authentication failed: {ex.Reason}");

    }}

    catch (Exception ex)catch (NetworkException ex)

    {{

        Console.WriteLine($"❌ Error during logout: {ex.Message}");    Console.WriteLine($"Network error: {ex.Message}");

    }}

}catch (InvalidTokenException ex)

```{

    Console.WriteLine($"Token error: {ex.Message}");

### Complete Example}

catch (StorageException ex)

Here's a complete console application example:{

    Console.WriteLine($"Storage error: {ex.Message}");

```csharp}

using System;```

using System.Threading.Tasks;

using BlitzWare.SDK;## 📊 Logging

using BlitzWare.SDK.Models;

using BlitzWare.SDK.Storage;```csharp

// Enable logging in configuration

class Programvar config = new BlitzWareConfig

{{

    private static BlitzWareAuth? _auth;    // ... other settings

    EnableLogging = true

    static async Task Main(string[] args)};

    {

        Console.WriteLine("BlitzWare .NET SDK - Console Example");// With Microsoft.Extensions.Logging (in .NET 6+)

        Console.WriteLine("====================================");var loggerFactory = LoggerFactory.Create(builder => builder.AddConsole());

        Console.WriteLine();var logger = loggerFactory.CreateLogger<BlitzWareAuth>();



        // Configurevar auth = new BlitzWareAuth(config, storage, logger);

        var config = new BlitzWareConfig```

        {

            ClientId = Environment.GetEnvironmentVariable("BLITZWARE_CLIENT_ID") ## 🧪 Testing

                ?? "your-client-id",

            RedirectUri = Environment.GetEnvironmentVariable("BLITZWARE_REDIRECT_URI") ```csharp

                ?? "http://localhost:8080/callback",// Use memory storage for testing

            ResponseType = "code",var config = new BlitzWareConfig { /* test config */ };

            EnableLogging = truevar storage = new MemorySecureStorage();

        };var auth = new BlitzWareAuth(config, storage);



        // Initialize// Mock authentication for testing

        var storage = new MemorySecureStorage();await storage.StoreTokenResponseAsync(new TokenResponse

        _auth = new BlitzWareAuth(config, storage);{

    AccessToken = "mock-access-token",

        // Subscribe to auth state changes    ExpiresIn = 3600

        _auth.AuthStateChanged += (sender, e) =>});

        {

            Console.WriteLine($"🔄 Auth state changed: {e.State}");await storage.StoreUserAsync(new BlitzWareUser

            {

            if (e.State == AuthState.Authenticated)    Id = "test-user",

            {    Name = "Test User",

                Console.WriteLine($"✅ User {e.User?.DisplayName} authenticated!");    Email = "test@example.com",

            }    Roles = new List<string> { "user" }

            else if (e.State == AuthState.Unauthenticated)});

            {

                Console.WriteLine("❌ User is no longer authenticated.");await auth.InitializeAsync();

            }// auth.IsAuthenticated should now be true

        };```



        await _auth.InitializeAsync();## 🔧 Advanced Usage



        if (_auth.IsAuthenticated)### Custom HTTP Client

        {

            Console.WriteLine("✅ User is already authenticated!");```csharp

            ShowUserInfo(_auth);var httpClient = new HttpClient();

        }httpClient.DefaultRequestHeaders.Add("X-Custom-Header", "value");

        else

        {var config = new BlitzWareConfig { /* ... */ };

            Console.WriteLine("🔑 User is not authenticated. Starting login...");var blitzWareHttpClient = new BlitzWareHttpClient(config, httpClient);

            await LoginAsync(_auth);```

        }

### Health Checks

        // Interactive menu

        await RunMenuAsync();```csharp

    }var httpClient = new BlitzWareHttpClient(config);



    private static async Task RunMenuAsync()// Check if BlitzWare domain is accessible

    {var isHealthy = await httpClient.HealthCheckAsync();

        while (true)

        {// Get OpenID Connect configuration

            Console.WriteLine();var oidcConfig = await httpClient.GetOidcConfigurationAsync();

            Console.WriteLine("Menu:");```

            Console.WriteLine("1. Show user info");

            Console.WriteLine("2. Check roles");### PKCE Utilities

            Console.WriteLine("3. Get access token");

            Console.WriteLine("4. Refresh token");```csharp

            Console.WriteLine("5. Logout");// Generate PKCE data manually

            Console.WriteLine("6. Exit");var pkceData = OAuthUtils.GeneratePKCE();

            Console.Write("Select option: ");Console.WriteLine($"Code Verifier: {pkceData.CodeVerifier}");

Console.WriteLine($"Code Challenge: {pkceData.CodeChallenge}");

            var input = Console.ReadLine();

// JWT token parsing (for reading claims only - does NOT verify signature)

            switch (input)var claims = OAuthUtils.ParseJwtClaims(accessToken);

            {var expiry = OAuthUtils.GetTokenExpiry(accessToken);

                case "1":var isExpired = OAuthUtils.IsTokenExpired(accessToken);

                    ShowUserInfo(_auth!);```

                    break;

                case "2":## 📚 Examples

                    CheckRoles(_auth!);

                    break;The SDK includes complete examples for:

                case "3":

                    await ShowAccessTokenAsync(_auth!);- ✅ **Console Application** - Command-line authentication flow

                    break;- ✅ **WinForms Application** - Windows desktop app with embedded browser

                case "4":- 🔄 **WPF Application** - Modern Windows desktop UI

                    await RefreshTokenAsync(_auth!);- 🔄 **MAUI Application** - Cross-platform mobile and desktop

                    break;- 🔄 **ASP.NET Core** - Web application integration

                case "5":- 🔄 **Blazor** - Client-side and server-side scenarios

                    await LogoutAsync(_auth!);- 🔄 **Unity** - Game development integration

                    break;

                case "6":## 🤝 Contributing

                    _auth?.Dispose();

                    return;1. Fork the repository

                default:2. Create a feature branch

                    Console.WriteLine("Invalid option");3. Make your changes

                    break;4. Add tests

            }5. Submit a pull request

        }

    }## 📄 License



    // Implement LoginAsync, ShowUserInfo, CheckRoles, etc. from previous stepsThis project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

}

```## 🆘 Support



---- 📧 Email: support@blitzware.com

- 💬 Discord: [BlitzWare Community](https://discord.gg/blitzware)

## Advanced Features- 📚 Documentation: [docs.blitzware.com](https://docs.blitzware.com)

- 🐛 Issues: [GitHub Issues](https://github.com/blitzware/blitzware-dotnet-sdk/issues)

### Secure Storage Options

## 🏗️ Roadmap

Choose the appropriate storage for your platform:

- [ ] WPF Example Application

```csharp- [ ] MAUI Cross-platform Example

// Windows - Use Credential Manager- [ ] Blazor WebAssembly Example

var storage = new WindowsCredentialStorage("YourAppName");- [ ] Unity Integration Example

- [ ] ASP.NET Core Identity Integration

// Development/Testing - Use memory storage- [ ] Azure Active Directory Integration

var storage = new MemorySecureStorage();- [ ] Single Sign-On (SSO) Support

- [ ] Biometric Authentication Support

// Auto-detect platform - Uses best available storage

var storage = new AutoSecureStorage("YourAppName");---

```

Made with ❤️ by the BlitzWare Team
### Error Handling

Handle authentication errors gracefully:

```csharp
try
{
    await auth.HandleCallbackAsync(callbackUrl);
}
catch (AuthenticationFailedException ex)
{
    Console.WriteLine($"Authentication failed: {ex.Reason}");
}
catch (NetworkException ex)
{
    Console.WriteLine($"Network error: {ex.Message}");
}
catch (InvalidTokenException ex)
{
    Console.WriteLine($"Token error: {ex.Message}");
}
catch (StorageException ex)
{
    Console.WriteLine($"Storage error: {ex.Message}");
}
```

### Logging (.NET 6.0+)

Enable logging for debugging:

```csharp
using Microsoft.Extensions.Logging;

var loggerFactory = LoggerFactory.Create(builder => 
{
    builder.AddConsole();
    builder.SetMinimumLevel(LogLevel.Debug);
});

var logger = loggerFactory.CreateLogger<BlitzWareAuth>();
var auth = new BlitzWareAuth(config, storage, logger);
```

### Session Validation

Check if the current session is still valid:

```csharp
private static async Task ValidateSessionAsync(BlitzWareAuth auth)
{
    var isValid = await auth.IsAuthenticatedAsync();
    
    if (isValid)
    {
        Console.WriteLine("✅ Session is valid");
    }
    else
    {
        Console.WriteLine("❌ Session expired. Please log in again.");
    }
}
```

---

## Important Notes

### Native App Logout Behavior

For native/desktop applications, the logout endpoint clears server-side session cookies. However, since OAuth authentication happens in the system browser (a separate process), the application cannot access these cookies. This is expected behavior and matches industry standards (Google OAuth, Auth0, etc.).

The logout process:
1. Calls the server `/logout` endpoint (best effort)
2. Clears all local tokens and user data
3. Updates auth state to `Unauthenticated`

**Note**: You may see "No user session found for logout" in server logs. This is normal for native apps - the local token clearing is the primary logout mechanism.

### Token Expiration

Tokens naturally expire based on their TTL (Time To Live). The SDK handles token refresh automatically when you call `GetAccessTokenAsync()`. You can also use token introspection to validate tokens server-side.

---

That's it! You now have a fully functional .NET application with BlitzWare authentication.

For more information, check out the [Console example app](https://github.com/LanderDK/blitzware-dotnet-sdk/tree/master/Examples/Console) which demonstrates all these features.
