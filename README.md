# .NET

This guide demonstrates how to add user authentication to a .NET application using BlitzWare.

This tutorial is based on the [example console app](https://github.com/LanderDK/blitzware-dotnet-sdk/tree/master/Examples/Console).

1. [Configure BlitzWare](#1-configure-blitzware)
2. [Install the BlitzWare .NET SDK](#2-install-the-blitzware-net-sdk)
3. [Implementation Guide](#3-implementation-guide)

---

## 1) Configure BlitzWare

### Get Your Application Keys

You will need some details about your application to communicate with BlitzWare. You can get these details from the **Application Settings** section in the BlitzWare dashboard.

**You need the Client ID.**

### Configure Redirect URIs

A redirect URI is a URL in your application where BlitzWare redirects the user after they have authenticated. The redirect URI for your app must be added to the **Redirect URIs** list in your **Application Settings** under the **Security** tab. If this is not set, users will be unable to log in to the application and will get an error.

For desktop applications, you can use a local URI such as `http://localhost:8080/callback`.

---

## 2) Install the BlitzWare .NET SDK

### Using NuGet Package Manager

```bash
Install-Package BlitzWare.SDK
```

### Using .NET CLI

```bash
dotnet add package BlitzWare.SDK
```

### Manual Installation

Clone the repository and reference the project directly:

```bash
git clone https://github.com/LanderDK/blitzware-dotnet-sdk.git
```

### Prerequisites

This SDK requires .NET Standard 2.0 or higher, which is compatible with:
- .NET Core 2.0+
- .NET 6.0+
- .NET Framework 4.6.1+

For .NET 6.0 or higher, additional logging features are available.

### Platform Support

- Windows Desktop (WPF, WinForms)
- Console Applications
- ASP.NET Core Web Applications
- Xamarin.Forms (iOS and Android)
- MAUI (iOS, Android, macOS, Windows)

---

## 3) Implementation Guide

Follow this step-by-step guide to implement authentication in your app.

### Step 1: Configure BlitzWare

Initialize the BlitzWare configuration with your application details:

```csharp
using BlitzWare.SDK;
using BlitzWare.SDK.Models;

// Initialize BlitzWare configuration
var config = new BlitzWareConfig
{
    ClientId = "your-client-id",
    RedirectUri = "http://localhost:8080/callback",
    ResponseType = "code", // OAuth 2.0 authorization code flow
    
    // Optional configurations
    AdditionalParameters = new Dictionary<string, string>
    {
        // Add any additional OAuth parameters here
    }
};
```

### Step 2: Initialize Authentication

Create an instance of the BlitzWare authentication client and initialize it:

```csharp
// Initialize BlitzWare auth
var auth = new BlitzWareAuth(config);

// Subscribe to auth state changes
auth.AuthStateChanged += (sender, args) =>
{
    Console.WriteLine($"Auth state changed to: {args.State}");
    if (args.User != null)
    {
        Console.WriteLine($"User: {args.User.Username}");
    }
};

// Initialize and check for existing session
await auth.InitializeAsync();

if (auth.IsAuthenticated)
{
    Console.WriteLine("User is already authenticated!");
    // Display user info or navigate to main screen
}
else
{
    Console.WriteLine("User is not authenticated. Starting login flow...");
    // Start the login flow
}
```

### Step 3: Implement Login Flow

Start the OAuth login flow and handle the callback:

```csharp
// Desktop/Console Application Example

// Start the login flow
var authRequest = await auth.StartLoginAsync();

// Open browser with the authorization URL
OpenBrowser(authRequest.AuthorizationUrl);

// Start local HTTP listener to capture the callback
// Here's a simplified example - see full code in the example project
string callbackUrl = await StartHttpListenerAsync(redirectUri.Port);

// Handle the callback
await auth.HandleCallbackAsync(callbackUrl);

// Helper method to open browser
private static void OpenBrowser(string url)
{
    try
    {
        Process.Start(url);
    }
    catch
    {
        // On Windows, use Process.Start with UseShellExecute
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            url = url.Replace("&", "^&");
            Process.Start(new ProcessStartInfo("cmd", $"/c start {url}") { CreateNoWindow = true });
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
            throw;
        }
    }
}
```

For WPF or Windows Forms applications:

```csharp
// WPF/WinForms specific implementation
private async Task StartLoginFlow()
{
    try
    {
        // Start the login flow
        var authRequest = await _auth.StartLoginAsync();
        
        // Open the browser
        Process.Start(new ProcessStartInfo
        {
            FileName = authRequest.AuthorizationUrl,
            UseShellExecute = true
        });
        
        // Start local HTTP server to listen for the callback
        var callbackUrl = await StartHttpListenerAsync();
        
        // Process the callback
        await _auth.HandleCallbackAsync(callbackUrl);
        
        if (_auth.IsAuthenticated)
        {
            // Update UI or navigate
            MainWindow.Content = new DashboardPage();
        }
    }
    catch (Exception ex)
    {
        MessageBox.Show($"Login failed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
    }
}
```

### Step 4: Display User Information

Access user information when authenticated:

```csharp
if (auth.IsAuthenticated && auth.User != null)
{
    var user = auth.User;
    
    Console.WriteLine($"User ID: {user.Id}");
    Console.WriteLine($"Username: {user.Username}");
    Console.WriteLine($"Email: {user.Email}");
    
    // Access roles
    Console.WriteLine("Roles:");
    foreach (var role in user.Roles)
    {
        Console.WriteLine($"- {role}");
    }
}
```

### Step 5: Access Token Management

Get access tokens for making authenticated API calls:

```csharp
// Get the current access token (auto-refreshes if needed)
var token = await auth.GetAccessTokenAsync();

if (!string.IsNullOrEmpty(token))
{
    using var client = new HttpClient();
    client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
    
    var response = await client.GetAsync("https://api.example.com/protected");
    if (response.IsSuccessStatusCode)
    {
        var content = await response.Content.ReadAsStringAsync();
        Console.WriteLine($"API Response: {content}");
    }
    else
    {
        Console.WriteLine($"API Error: {response.StatusCode}");
    }
}
```

### Step 6: Role-Based Access Control

Implement role-based features:

```csharp
var user = auth.User;

if (user != null)
{
    // Check for specific roles
    if (user.HasRole("admin"))
    {
        // Show admin features
        ShowAdminPanel();
    }
    
    // Check for any of these roles
    if (user.HasAnyRole(new[] { "premium", "pro", "subscriber" }))
    {
        // Show premium features
        EnablePremiumFeatures();
    }
    
    // Check for all required roles
    if (user.HasAllRoles(new[] { "editor", "reviewer" }))
    {
        // Show content publishing features
        ShowPublishingTools();
    }
}
```

### Step 7: Session Validation

Validate the user's session:

```csharp
// Check if the session is still valid
bool isValid = await auth.ValidateSessionAsync();

if (isValid)
{
    Console.WriteLine("Session is valid!");
}
else
{
    Console.WriteLine("Session expired. Please log in again.");
    await auth.LogoutAsync();
    // Redirect to login
}
```

### Step 8: Logging Out

Implement logout functionality:

```csharp
// Log out the current user
await auth.LogoutAsync();

Console.WriteLine("Logged out successfully!");
// Navigate back to login screen
```

### Step 9: Custom Storage

By default, the SDK uses platform-specific secure storage. You can provide your own implementation:

```csharp
// Implement the ISecureStorage interface
public class CustomStorage : ISecureStorage
{
    // Implementation methods...
}

// Use your custom storage
var customStorage = new CustomStorage();
var auth = new BlitzWareAuth(config, customStorage);
```

## Platform-Specific Implementation

### WPF Example

```csharp
// MainWindow.xaml.cs
public partial class MainWindow : Window
{
    private readonly BlitzWareAuth _auth;
    
    public MainWindow()
    {
        InitializeComponent();
        
        // Initialize BlitzWare
        var config = new BlitzWareConfig
        {
            ClientId = "your-client-id",
            RedirectUri = "http://localhost:8080/callback",
            ResponseType = "code"
        };
        
        _auth = new BlitzWareAuth(config);
        _auth.AuthStateChanged += OnAuthStateChanged;
        
        Loaded += OnWindowLoaded;
    }
    
    private async void OnWindowLoaded(object sender, RoutedEventArgs e)
    {
        await _auth.InitializeAsync();
        UpdateUI();
    }
    
    private void OnAuthStateChanged(object sender, AuthStateChangedEventArgs e)
    {
        Dispatcher.Invoke(() => {
            UpdateUI();
        });
    }
    
    private void UpdateUI()
    {
        if (_auth.IsAuthenticated)
        {
            MainContent.Content = new DashboardPage(_auth);
        }
        else
        {
            MainContent.Content = new LoginPage(_auth);
        }
    }
}
```

### ASP.NET Core Web App Example

```csharp
// Startup.cs
public void ConfigureServices(IServiceCollection services)
{
    // Add BlitzWare authentication
    services.AddSingleton<BlitzWareConfig>(sp => new BlitzWareConfig
    {
        ClientId = Configuration["BlitzWare:ClientId"],
        RedirectUri = Configuration["BlitzWare:RedirectUri"],
        ResponseType = "code"
    });
    
    services.AddSingleton<BlitzWareAuth>();
    services.AddControllersWithViews();
}
```

---

That's it! You now have a fully functional .NET application with BlitzWare authentication.

For more information, check out the [example console app](https://github.com/LanderDK/blitzware-dotnet-sdk/tree/master/Examples/Console) which demonstrates all these features and more.