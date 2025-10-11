// BlitzWare .NET SDK - Windows Credential Manager Storage Implementation
// Copyright (c) 2025 BlitzWare. All rights reserved.

using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using System.Threading.Tasks;
using BlitzWare.SDK.Models;

namespace BlitzWare.SDK.Storage
{
#if NET5_0_OR_GREATER
    [SupportedOSPlatform("windows")]
#endif
    /// <summary>
    /// Windows Credential Manager implementation of secure storage
    /// Uses the Windows Credential Manager to securely store tokens and user data
    /// </summary>
    public class WindowsCredentialStorage : ISecureStorage
    {
        private const string TargetPrefix = "BlitzWare_";
        private readonly string _applicationName;

        /// <summary>
        /// Initialize Windows Credential storage
        /// </summary>
        /// <param name="applicationName">Application name for credential naming</param>
        public WindowsCredentialStorage(string applicationName = "BlitzWareApp")
        {
            if (string.IsNullOrWhiteSpace(applicationName))
                throw new ArgumentException("Application name cannot be null or empty", nameof(applicationName));

            _applicationName = applicationName;
        }

        /// <inheritdoc />
        public string StorageType => "Windows Credential Manager";

        /// <inheritdoc />
        public Task SetAsync(string key, string value)
        {
            if (string.IsNullOrEmpty(key))
                throw new ArgumentException("Key cannot be null or empty", nameof(key));

            if (value == null)
                throw new ArgumentNullException(nameof(value));

            try
            {
                var targetName = GetTargetName(key);
                var credentialBytes = Encoding.UTF8.GetBytes(value);
                var credentialPtr = Marshal.AllocHGlobal(credentialBytes.Length);
                
                try
                {
                    Marshal.Copy(credentialBytes, 0, credentialPtr, credentialBytes.Length);
                    
                    var credential = new CREDENTIAL
                    {
                        TargetName = targetName,
                        Type = CRED_TYPE.GENERIC,
                        UserName = _applicationName,
                        CredentialBlob = credentialPtr,
                        CredentialBlobSize = (uint)credentialBytes.Length,
                        Persist = CRED_PERSIST.LOCAL_MACHINE,
                        AttributeCount = 0,
                        Attributes = IntPtr.Zero,
                        TargetAlias = null,
                        Comment = "BlitzWare SDK Authentication Data"
                    };

                    if (!CredWrite(ref credential, 0))
                    {
                        var error = Marshal.GetLastWin32Error();
                        throw new StorageException($"Failed to write credential: {error}");
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(credentialPtr);
                }

                return Task.CompletedTask;
            }
            catch (Exception ex) when (!(ex is StorageException))
            {
                throw new StorageException($"Failed to store value for key '{key}'", ex);
            }
        }

        /// <inheritdoc />
        public Task<string?> GetAsync(string key)
        {
            if (string.IsNullOrEmpty(key))
                throw new ArgumentException("Key cannot be null or empty", nameof(key));

            try
            {
                var targetName = GetTargetName(key);

                if (!CredRead(targetName, CRED_TYPE.GENERIC, 0, out var credentialPtr))
                {
                    var error = Marshal.GetLastWin32Error();
                    if (error == ERROR_NOT_FOUND)
                        return Task.FromResult<string?>(null);

                    throw new StorageException($"Failed to read credential: {error}");
                }

                try
                {
                    var credential = Marshal.PtrToStructure<CREDENTIAL>(credentialPtr);
                    if (credential.CredentialBlob == IntPtr.Zero || credential.CredentialBlobSize == 0)
                        return Task.FromResult<string?>(null);

                    var bytes = new byte[credential.CredentialBlobSize];
                    Marshal.Copy(credential.CredentialBlob, bytes, 0, (int)credential.CredentialBlobSize);
                    var value = Encoding.UTF8.GetString(bytes);

                    return Task.FromResult<string?>(value);
                }
                finally
                {
                    CredFree(credentialPtr);
                }
            }
            catch (Exception ex) when (!(ex is StorageException))
            {
                throw new StorageException($"Failed to retrieve value for key '{key}'", ex);
            }
        }

        /// <inheritdoc />
        public Task RemoveAsync(string key)
        {
            if (string.IsNullOrEmpty(key))
                throw new ArgumentException("Key cannot be null or empty", nameof(key));

            try
            {
                var targetName = GetTargetName(key);

                if (!CredDelete(targetName, CRED_TYPE.GENERIC, 0))
                {
                    var error = Marshal.GetLastWin32Error();
                    if (error != ERROR_NOT_FOUND)
                    {
                        throw new StorageException($"Failed to delete credential: {error}");
                    }
                }

                return Task.CompletedTask;
            }
            catch (Exception ex) when (!(ex is StorageException))
            {
                throw new StorageException($"Failed to remove value for key '{key}'", ex);
            }
        }

        /// <inheritdoc />
        public Task<bool> ContainsKeyAsync(string key)
        {
            if (string.IsNullOrEmpty(key))
                throw new ArgumentException("Key cannot be null or empty", nameof(key));

            try
            {
                var targetName = GetTargetName(key);

                if (!CredRead(targetName, CRED_TYPE.GENERIC, 0, out var credentialPtr))
                {
                    var error = Marshal.GetLastWin32Error();
                    return Task.FromResult(error != ERROR_NOT_FOUND);
                }

                CredFree(credentialPtr);
                return Task.FromResult(true);
            }
            catch (Exception ex)
            {
                throw new StorageException($"Failed to check existence of key '{key}'", ex);
            }
        }

        /// <inheritdoc />
        public Task ClearAsync()
        {
            try
            {
                // Enumerate all credentials with our target prefix and delete them
                if (CredEnumerate($"{TargetPrefix}{_applicationName}_*", 0, out var count, out var credentialsPtr))
                {
                    try
                    {
                        for (int i = 0; i < count; i++)
                        {
                            var credentialPtr = Marshal.ReadIntPtr(credentialsPtr, i * IntPtr.Size);
                            var credential = Marshal.PtrToStructure<CREDENTIAL>(credentialPtr);
                            
                            if (credential.TargetName != null)
                            {
                                CredDelete(credential.TargetName, CRED_TYPE.GENERIC, 0);
                            }
                        }
                    }
                    finally
                    {
                        CredFree(credentialsPtr);
                    }
                }

                return Task.CompletedTask;
            }
            catch (Exception ex)
            {
                throw new StorageException("Failed to clear credentials", ex);
            }
        }

        /// <summary>
        /// Get the Windows Credential Manager target name for a key
        /// </summary>
        /// <param name="key">Storage key</param>
        /// <returns>Target name</returns>
        private string GetTargetName(string key)
        {
            return $"{TargetPrefix}{_applicationName}_{key}";
        }

        /// <summary>
        /// Check if Windows Credential Manager is available
        /// </summary>
        /// <returns>True if available</returns>
        public static bool IsAvailable()
        {
            try
            {
                return RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
            }
            catch
            {
                return false;
            }
        }

        #region Windows API Declarations

        private const int ERROR_NOT_FOUND = 1168;

        [StructLayout(LayoutKind.Sequential)]
        private struct CREDENTIAL
        {
            public uint Flags;
            public CRED_TYPE Type;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string? TargetName;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string? Comment;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
            public uint CredentialBlobSize;
            public IntPtr CredentialBlob;
            public CRED_PERSIST Persist;
            public uint AttributeCount;
            public IntPtr Attributes;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string? TargetAlias;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string? UserName;
        }

        private enum CRED_TYPE : uint
        {
            GENERIC = 1,
            DOMAIN_PASSWORD = 2,
            DOMAIN_CERTIFICATE = 3,
            DOMAIN_VISIBLE_PASSWORD = 4,
            GENERIC_CERTIFICATE = 5,
            DOMAIN_EXTENDED = 6,
            MAXIMUM = 7,
            MAXIMUM_EX = (MAXIMUM + 1000)
        }

        private enum CRED_PERSIST : uint
        {
            SESSION = 1,
            LOCAL_MACHINE = 2,
            ENTERPRISE = 3
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CredWrite([In] ref CREDENTIAL userCredential, [In] uint flags);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CredRead(string target, CRED_TYPE type, int reservedFlag, out IntPtr credentialPtr);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CredDelete(string target, CRED_TYPE type, int reservedFlag);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CredEnumerate(string? filter, int flag, out int count, out IntPtr pCredentials);

        [DllImport("advapi32.dll")]
        private static extern void CredFree([In] IntPtr buffer);

        #endregion
    }

    /// <summary>
    /// Cross-platform secure storage that automatically selects the best implementation
    /// </summary>
    public class AutoSecureStorage : ISecureStorage
    {
        private readonly ISecureStorage _implementation;

        /// <summary>
        /// Initialize auto secure storage with the best available implementation
        /// </summary>
        /// <param name="applicationName">Application name for storage</param>
        /// <param name="fallbackToMemory">Whether to fallback to in-memory storage if no secure storage is available</param>
        public AutoSecureStorage(string applicationName = "BlitzWareApp", bool fallbackToMemory = true)
        {
            if (WindowsCredentialStorage.IsAvailable())
            {
                _implementation = new WindowsCredentialStorage(applicationName);
            }
            else if (fallbackToMemory)
            {
                _implementation = new MemorySecureStorage();
            }
            else
            {
                throw new NotSupportedException("No secure storage implementation available for this platform");
            }
        }

        /// <summary>
        /// Initialize auto secure storage with a specific implementation
        /// </summary>
        /// <param name="implementation">Storage implementation to use</param>
        public AutoSecureStorage(ISecureStorage implementation)
        {
            _implementation = implementation ?? throw new ArgumentNullException(nameof(implementation));
        }

        /// <inheritdoc />
        public string StorageType => _implementation.StorageType;

        /// <inheritdoc />
        public Task SetAsync(string key, string value) => _implementation.SetAsync(key, value);

        /// <inheritdoc />
        public Task<string?> GetAsync(string key) => _implementation.GetAsync(key);

        /// <inheritdoc />
        public Task RemoveAsync(string key) => _implementation.RemoveAsync(key);

        /// <inheritdoc />
        public Task<bool> ContainsKeyAsync(string key) => _implementation.ContainsKeyAsync(key);

        /// <inheritdoc />
        public Task ClearAsync() => _implementation.ClearAsync();
    }

    /// <summary>
    /// In-memory implementation of secure storage (for development/testing)
    /// WARNING: This is not secure and should only be used for development
    /// </summary>
    public class MemorySecureStorage : ISecureStorage
    {
        private readonly System.Collections.Concurrent.ConcurrentDictionary<string, string> _storage = new();

        /// <inheritdoc />
        public string StorageType => "In-Memory (Development Only)";

        /// <inheritdoc />
        public Task SetAsync(string key, string value)
        {
            if (string.IsNullOrEmpty(key))
                throw new ArgumentException("Key cannot be null or empty", nameof(key));

            _storage[key] = value ?? string.Empty;
            return Task.CompletedTask;
        }

        /// <inheritdoc />
        public Task<string?> GetAsync(string key)
        {
            if (string.IsNullOrEmpty(key))
                throw new ArgumentException("Key cannot be null or empty", nameof(key));

            _storage.TryGetValue(key, out var value);
            return Task.FromResult(value);
        }

        /// <inheritdoc />
        public Task RemoveAsync(string key)
        {
            if (string.IsNullOrEmpty(key))
                throw new ArgumentException("Key cannot be null or empty", nameof(key));

            _storage.TryRemove(key, out _);
            return Task.CompletedTask;
        }

        /// <inheritdoc />
        public Task<bool> ContainsKeyAsync(string key)
        {
            if (string.IsNullOrEmpty(key))
                throw new ArgumentException("Key cannot be null or empty", nameof(key));

            return Task.FromResult(_storage.ContainsKey(key));
        }

        /// <inheritdoc />
        public Task ClearAsync()
        {
            _storage.Clear();
            return Task.CompletedTask;
        }
    }
}