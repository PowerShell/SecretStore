// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.PowerShell.SecretManagement;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Management.Automation;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;

using Dbg = System.Diagnostics.Debug;

namespace Microsoft.PowerShell.SecretStore
{
    #region Utils

    internal static class Utils
    {
        #region Members

        internal const string PasswordRequiredMessage = "A valid password is required to access the Microsoft.PowerShell.SecretStore vault.\nUse the Unlock-SecretStore cmdlet to provide the required password to access the store.";

        #endregion

        #region Separators

        internal static class Separators
        {
            public static readonly char[] Backslash = new char[] { '\\' };
        }

        #endregion

        #region Constructor

        static Utils()
        {
            IsWindows = System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(
                System.Runtime.InteropServices.OSPlatform.Windows);
        }

        #endregion

        #region Properties

        public static bool IsWindows { get; }

        #endregion

        #region Methods

        /// <summary>
        /// Return current logged in user name in all upper case.
        /// WindowsIdentity.GetCurrent().Name does not always return account user
        /// name with correct casing (e.g., AD domain account with RunAs), and name
        /// casing needs to be consistent for encryption.
        /// </summary>
        /// <param name="origCharCasing">
        /// When true, user name is returned with char casing from system.
        /// This is needed for backward compatibility when reading from older stores
        /// encrypted with original character casing.
        /// </param>
        public static string GetCurrentUserName(
            bool origCharCasing = false)
        {
            if (IsWindows)
            {
                try
                {
                    var nameParts = WindowsIdentity.GetCurrent().Name.Split(Separators.Backslash);
                    switch (nameParts.Length)
                    {
                        case 1:
                            return origCharCasing ? nameParts[0] : nameParts[0].ToUpper();

                        case 2:
                            // 'DOMAIN\UserName'
                            return origCharCasing ? nameParts[1] : nameParts[1].ToUpper();
                    }
                }
                catch (SecurityException) { }
            }

            return origCharCasing ? Environment.UserName : Environment.UserName.ToUpper();
        }

        public static PSObject ConvertJsonToPSObject(string json)
        {
            var results = PowerShellInvoker.InvokeScriptCommon<PSObject>(
                script: @"param ([string] $json) Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $json",
                args: new object[] { json },
                error: out ErrorRecord _);

            return (results.Count > 0) ? results[0] : null;
        }

        public static string ConvertHashtableToJson(Hashtable hashtable)
        {
            var results = PowerShellInvoker.InvokeScriptCommon<string>(
                script: @"param ([hashtable] $hashtable) Microsoft.PowerShell.Utility\ConvertTo-Json -InputObject $hashtable -Depth 5",
                args: new object[] { hashtable },
                error: out ErrorRecord _);

            return (results.Count > 0) ? results[0] : null;
        }

        public static bool GetSecureStringFromData(
            byte[] data,
            out SecureString outSecureString)
        {
            if ((data.Length % 2) != 0)
            {
                Dbg.Assert(false, "Blob length for SecureString secure must be even.");
                outSecureString = null;
                return false;
            }

            outSecureString = new SecureString();
            var strLen = data.Length / 2;
            for (int i=0; i < strLen; i++)
            {
                int index = (2 * i);

                var ch = (char)(data[index + 1] * 256 + data[index]);
                outSecureString.AppendChar(ch);
            }

            return true;
        }

        public static bool GetDataFromSecureString(
            SecureString secureString,
            out byte[] data)
        {
            IntPtr ptr = Marshal.SecureStringToCoTaskMemUnicode(secureString);
            if (ptr != IntPtr.Zero)
            {
                try
                {
                    data = new byte[secureString.Length * 2];
                    Marshal.Copy(ptr, data, 0, data.Length);
                    return true;
                }
                finally
                {
                    Marshal.ZeroFreeCoTaskMemUnicode(ptr);
                }
            }

            data = null;
            return false;
        }

        private static bool ComparePasswords(
            SecureString password1,
            SecureString password2)
        {
            if (password1.Length != password2.Length)
            {
                return false;
            }

            IntPtr ptrPassword1 = IntPtr.Zero;
            IntPtr ptrPassword2 = IntPtr.Zero;
            try
            {
                ptrPassword1 = Marshal.SecureStringToCoTaskMemUnicode(password1);
                ptrPassword2 = Marshal.SecureStringToCoTaskMemUnicode(password2);
                if (ptrPassword1 != IntPtr.Zero && ptrPassword2 != IntPtr.Zero)
                {
                    for (int i=0; i<(password1.Length * 2); i++)
                    {
                        if (Marshal.ReadByte(ptrPassword1, i) != Marshal.ReadByte(ptrPassword2, i))
                        {
                            return false;
                        }
                    }

                    return true;
                }
            }
            finally
            {
                if (ptrPassword1 != IntPtr.Zero)
                {
                    Marshal.ZeroFreeCoTaskMemUnicode(ptrPassword1);
                }

                if (ptrPassword2 != IntPtr.Zero)
                {
                    Marshal.ZeroFreeCoTaskMemUnicode(ptrPassword2);
                }
            }

            return false;
        }

        public static SecureString PromptForPassword(
            PSCmdlet cmdlet,
            bool verifyPassword = false,
            string message = null)
        {
            if (cmdlet.Host is null || cmdlet.Host.UI is null)
            {
                throw new PSInvalidOperationException(
                    "Cannot prompt for password. No host available.");
            }

            SecureString password = null;

            cmdlet.Host.UI.WriteLine(
                string.IsNullOrEmpty(message) ? 
                    "A password is required for Microsoft.PowerShell.SecretStore vault."
                    : message);

            var isVerified = false;
            do
            {
                // Initial prompt
                cmdlet.Host.UI.WriteLine("Enter password:");
                password = cmdlet.Host.UI.ReadLineAsSecureString();
                if (password.Length == 0)
                {
                    cmdlet.Host.UI.WriteLine("\nThe entered password cannot be empty.  Please re-enter the password.\n");
                    continue;
                }

                if (verifyPassword)
                {
                    // Verification prompt
                    cmdlet.Host.UI.WriteLine("Enter password again for verification:");
                    var passwordVerified = cmdlet.Host.UI.ReadLineAsSecureString();

                    isVerified = ComparePasswords(password, passwordVerified);

                    if (!isVerified)
                    {
                        cmdlet.Host.UI.WriteLine("\nThe two entered passwords do not match.  Please re-enter the passwords.\n");
                    }
                }
                else
                {
                    isVerified = true;
                }
            } while (!isVerified);

            return password;
        }

        public static SecureString CheckPassword(SecureString password)
        {
            if (password != null && password.Length == 0)
            {
                throw new PSInvalidOperationException("A password cannot be empty.");
            }

            return password?.Copy() ?? null;
        }

        #endregion
    }

    #endregion

    #region SecureStore

    #region CryptoUtils

    internal static class CryptoUtils
    {
        #region Private members

        private static byte[] salt = new byte[32]
        {
            154, 146, 58, 204, 7, 124, 237, 132,
            248, 95, 158, 243, 108, 235, 163, 103,
            148, 95, 205, 190, 109, 184, 116, 92,
            155, 12, 6, 99, 0, 91, 54, 250
        };

        #endregion

        #region Public methods

        public static AesKey GenerateKey()
        {
            // By default this creates a 256 AES key with 128 block size.
            // IV size then, is 16.
            byte[] key;
            byte[] iv;
            using (var aes = Aes.Create())
            {
                key = aes.Key;
                iv = new byte[aes.BlockSize / 8];
            }
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(iv);
            }

            return new AesKey(key, iv);
        }

        public static AesKey GenerateKeyFromUserName(
            bool useOrigUserNameCasing = false)
        {
            var key = DeriveKeyFromPassword(
                passwordData: Encoding.UTF8.GetBytes(Utils.GetCurrentUserName(useOrigUserNameCasing)),
                keyLength: 32);

            var iv = new byte[16];  // Zero IV.
            
            return new AesKey(key, iv);
        }

        public static byte[] EncryptWithKey(
            SecureString passWord,
            AesKey key,
            byte[] data)
        {
            var keyToUse = DeriveKeyFromKeyAndPasswordOrUser(passWord, key);
            try
            {
                using (var aes = Aes.Create())
                {
                    aes.Key = keyToUse.Key;
                    aes.IV = keyToUse.IV;
                    using (var encryptor = aes.CreateEncryptor())
                    using (var sourceStream = new MemoryStream(data))
                    using (var targetStream = new MemoryStream())
                    {
                        using (var cryptoStream = new CryptoStream(targetStream, encryptor, CryptoStreamMode.Write))
                        {
                            sourceStream.CopyTo(cryptoStream);
                        }

                        return targetStream.ToArray();
                    }
                }
            }
            finally
            {
                keyToUse.Clear();
            }
        }

        /// <summary>
        /// Decrypts data with provided key and password value.
        /// If no password, current user name is used to derive final key.
        /// If decryption fails, it is retried with older version of username with
        /// original character casing.
        /// </summary>
        public static byte[] DecryptWithKeyWithRetry(
            SecureString passWord,
            AesKey key,
            byte[] data)
        {
            try
            {
                return DecryptWithKey(
                    passWord,
                    key,
                    data,
                    useOrigUserNameCasing: false);
            }
            catch (CryptographicException)
            {
                if (!(passWord is null))
                {
                    throw new PasswordRequiredException(Utils.PasswordRequiredMessage);
                }
            }
            
            // Retry but with original user name casing.
            // This only applies when passWord is null, and username is substituted for key derivation.
            try
            {
                return DecryptWithKey(
                    passWord,
                    key,
                    data,
                    useOrigUserNameCasing: true);
            }
            catch (CryptographicException)
            {
                throw new PasswordRequiredException(Utils.PasswordRequiredMessage);
            }
        }

        /// <summary>
        /// Decrypts data with no provided key, and uses current UserName to derive
        /// the key.
        /// UserName is converted to all upper case to ensure it is consistent.
        /// (Workaround for bug: Windows AD account user name char casing).
        /// If decryption fails, it is retried with older version of UserName with
        /// original character casing.
        /// </summary>
        public static byte[] DecryptWithNoKeyWithRetry(
            byte[] data)
        {
            var encryptKey = GenerateKeyFromUserName(useOrigUserNameCasing: false);
            try
            {
                return DecryptWithKey(
                    passWord: null,
                    key: encryptKey,
                    data: data,
                    useOrigUserNameCasing: false);
            }
            catch (CryptographicException) { }
            finally
            {
                encryptKey.Clear();
            }

            // Retry but with original user name casing.
            encryptKey = GenerateKeyFromUserName(useOrigUserNameCasing: true);
            try
            {
                return DecryptWithKey(
                    passWord: null,
                    key: encryptKey,
                    data: data,
                    useOrigUserNameCasing: true);
            }
            finally
            {
                encryptKey.Clear();
            }
        }

        /// <summary>
        /// Decrypt data key and password value.
        /// If no password, then current user name is used to derive final key.
        /// </summary>
        private static byte[] DecryptWithKey(
            SecureString passWord,
            AesKey key,
            byte[] data,
            bool useOrigUserNameCasing = false)
        {
            var keyToUse = DeriveKeyFromKeyAndPasswordOrUser(passWord, key, useOrigUserNameCasing);
            try
            {
                using (var aes = Aes.Create())
                {
                    aes.Key = keyToUse.Key;
                    aes.IV = keyToUse.IV;
                    using (var decryptor = aes.CreateDecryptor())
                    using (var sourceStream = new MemoryStream(data))
                    using (var targetStream = new MemoryStream())
                    {
                        using (var cryptoStream = new CryptoStream(sourceStream, decryptor, CryptoStreamMode.Read))
                        {
                            cryptoStream.CopyTo(targetStream);
                        }

                        return targetStream.ToArray();
                    }
                }
            }
            finally
            {
                keyToUse.Clear();
            }
        }

        public static byte[] ComputeHashWithPasswordOrUser(
            SecureString passWord,
            byte[] dataToHash)
        {
            byte[] keyToUse = DeriveKeyFromPasswordOrUser(passWord);
            try
            {
                return ComputeHash(keyToUse, dataToHash);
            }
            finally
            {
                ZeroOutData(keyToUse);
            }
        }

        /// <summary>
        /// Validates provided data blob with the provide hash value.
        /// Hash is computed with a key derived from the provided password, or
        /// the current UserName if no password.
        /// UserName is returned in all upper case to ensure consistency.
        /// (Workaround for bug: Windows AD account user name char casing).
        /// If validation fails, it is retried with older version of UserName with
        /// original character casing.
        /// </summary>
        public static bool ValidateHashWithPasswordOrUser(
            SecureString passWord,
            byte[] hash,
            byte[] dataToValidate)
        {
            var keyToUse = DeriveKeyFromPasswordOrUser(passWord, useOrigUserNameCasing: false);
            try
            {
                bool isValid = ValidateHash(
                    key: keyToUse,
                    hashToCompare: hash,
                    dataToValidate: dataToValidate);

                if (!isValid && passWord is null)
                {
                    // Try again but with original user name character casing,
                    // in case this is older encrypted data.
                    ZeroOutData(keyToUse);
                    keyToUse = DeriveKeyFromPasswordOrUser(passWord, useOrigUserNameCasing: true);
                    isValid = ValidateHash(
                        key: keyToUse,
                        hashToCompare: hash,
                        dataToValidate: dataToValidate);
                }

                return isValid;
            }
            finally
            {
                ZeroOutData(keyToUse);
            }
        }

        public static void ZeroOutData(byte[] data)
        {
            if (data is null) { return; }
            for (int i = 0; i < data.Length; i++)
            {
                data[i] = 0;
            }
        }

        #endregion

        #region Private methods

        private static byte[] GetPasswordOrUserData(
            SecureString passWord,
            bool useOrigUserNameCasing = false)
        {
            if (passWord is null)
            {
                return Encoding.UTF8.GetBytes(
                    Utils.GetCurrentUserName(useOrigUserNameCasing));
            }

            if (Utils.GetDataFromSecureString(
                secureString: passWord,
                data: out byte[] passWordData))
            {
                return passWordData;
            }

            throw new PSInvalidOperationException("Unable to read password data from SecureString.");
        }

        private static AesKey DeriveKeyFromKeyAndPasswordOrUser(
            SecureString passWord,
            AesKey key,
            bool useOrigUserNameCasing = false)
        {            
            var passWordData = GetPasswordOrUserData(passWord, useOrigUserNameCasing);
            try
            {
                byte[] newKey;
                using (var derivedBytes = new Rfc2898DeriveBytes(
                    password: passWordData, 
                    salt: key.Key, 
                    iterations: 1000))
                {
                    newKey = derivedBytes.GetBytes(key.Key.Length);
                }

                byte[] newIV;
                using (var derivedBytes = new Rfc2898DeriveBytes(
                    password: passWordData,
                    salt: key.IV,
                    iterations: 1000))
                {
                    newIV = derivedBytes.GetBytes(key.IV.Length);
                }

                return new AesKey(
                    key: newKey,
                    iv: newIV);
            }
            finally
            {
                ZeroOutData(passWordData);
            }
        }

        private static byte[] DeriveKeyFromPasswordOrUser(
            SecureString passWord,
            bool useOrigUserNameCasing = false)
        {
            // Create hash key with either provided password or current user name.
            var passWordData = GetPasswordOrUserData(passWord, useOrigUserNameCasing);
            return DeriveKeyFromPassword(
                passwordData: passWordData,
                keyLength: 64);
        }

        private static byte[] DeriveKeyFromPassword(
            byte[] passwordData,
            int keyLength)
        {
            try
            {
                using (var derivedBytes = new Rfc2898DeriveBytes(
                    password: passwordData, 
                    salt: salt, 
                    iterations: 1000))
                {
                    return derivedBytes.GetBytes(keyLength);
                }
            }
            finally
            {
                ZeroOutData(passwordData);
            }
        }

        private static byte[] ComputeHash(
            byte[] key,
            byte[] dataToHash)
        {
            using (var hMac = new HMACSHA256(key))
            {
                return hMac.ComputeHash(dataToHash);
            }
        }

        private static bool ValidateHash(
            byte[] key,
            byte[] hashToCompare,
            byte[] dataToValidate)
        {
            var computedHash = ComputeHash(
                key: key,
                dataToHash: dataToValidate);
            
            if (hashToCompare.Length != computedHash.Length)
            {
                return false;
            }

            for (int i=0; i<hashToCompare.Length; i++)
            {
                if (hashToCompare[i] != computedHash[i])
                {
                    return false;
                }
            }

            return true;
        }

        #endregion
    }

    #endregion

    #region Public Enums

    public enum SecureStoreScope
    {
        CurrentUser = 1,
        AllUsers
    }

    public enum Authenticate
    {
        None = 0,
        Password = 1
    }

    public enum Interaction
    {
        None = 0,
        Prompt = 1
    }

    #endregion

    #region SecureStoreConfig

    internal sealed class SecureStoreConfig
    {
        #region Public Properties

        public SecureStoreScope Scope 
        {
            get;
            private set;
        }

        public Authenticate Authentication
        {
            get;
            private set;
        }

        /// <Summary>
        /// Password timeout time in seconds
        /// </Summary>
        public int PasswordTimeout
        {
            get;
            private set;
        }

        public Interaction Interaction
        {
            get;
            private set;
        }

        #endregion

        #region Internal Properties

        internal bool PasswordRequired
        {
            get;
            private set;
        }

        #endregion

        #region Constructor

        private SecureStoreConfig()
        {
        }

        public SecureStoreConfig(
            SecureStoreScope scope,
            Authenticate authentication,
            int passwordTimeout,
            Interaction interaction)
        {
            Scope = scope;
            PasswordTimeout = passwordTimeout;
            Authentication = authentication;
            Interaction = interaction;

            PasswordRequired = authentication == Authenticate.Password;
        }

        public SecureStoreConfig(
            string json)
        {
            ConvertFromJson(json);
        }

        #endregion

        #region Public methods

        public string ConvertToJson()
        {
            // Config data
            var configHashtable = new Hashtable();
            configHashtable.Add(
                key: "StoreScope",
                value: Scope);
            configHashtable.Add(
                key: "Authentication",
                value: Authentication);
            configHashtable.Add(
                key: "PasswordTimeout",
                value: PasswordTimeout);
            configHashtable.Add(
                key: "Interaction",
                value: Interaction);

            var dataDictionary = new Hashtable();
            dataDictionary.Add(
                key: "ConfigData",
                value: configHashtable);

            return Utils.ConvertHashtableToJson(dataDictionary);
        }

        #endregion

        #region Private methods

        private void ConvertFromJson(string json)
        {
            dynamic configDataObj = (Utils.ConvertJsonToPSObject(json));
            if (configDataObj is null)
            {
                throw new InvalidDataException("Unable to read store configuration json data.");
            }

            Scope = (SecureStoreScope) configDataObj.ConfigData.StoreScope;
            Authentication = (Authenticate) configDataObj.ConfigData.Authentication;
            PasswordTimeout = (int) configDataObj.ConfigData.PasswordTimeout;
            Interaction = (Interaction) configDataObj.ConfigData.Interaction;

            PasswordRequired = Authentication == Authenticate.Password;
        }

        #endregion

        #region Static methods

        public static SecureStoreConfig GetDefault()
        {
            return new SecureStoreConfig(
                scope: SecureStoreScope.CurrentUser,
                authentication: Authenticate.Password,
                passwordTimeout: 900,
                interaction: Interaction.Prompt);
        }

        #endregion
    }

    #endregion

    #region SecureStoreMetada

    internal sealed class SecureStoreMetadata
    {
        #region Properties

        public string Name
        {
            get;
        }

        public string TypeName
        {
            get;
        }

        public int Offset
        {
            get;
            set;
        }

        public int Size
        {
            get;
        }

        public ReadOnlyDictionary<string, object> Attributes
        {
            get;
        }

        public ReadOnlyDictionary<string, object> AdditionalData
        {
            get;
        }

        public Hashtable AttributesAsHashtable
        {
            get 
            {
                return ConvertToHashtable(Attributes);
            }
        }

        public Hashtable AdditionalDataAsHashtable
        {
            get
            {
                return ConvertToHashtable(AdditionalData);
            }
        }

        #endregion

        #region Constructor

        private SecureStoreMetadata()
        {
        }

        public SecureStoreMetadata(
            string name,
            string typeName,
            int offset,
            int size,
            ReadOnlyDictionary<string, object> attributes,
            ReadOnlyDictionary<string, object> additionalData)
        {
            Name = name;
            TypeName = typeName;
            Offset = offset;
            Size = size;
            Attributes = attributes;
            AdditionalData = additionalData;
        }

        public SecureStoreMetadata(
            SecureStoreMetadata metadata)
        {
            Name = metadata.Name;
            TypeName = metadata.TypeName;
            Offset = metadata.Offset;
            Size = metadata.Size;
            Attributes = metadata.Attributes;
            AdditionalData = metadata.AdditionalData;
        }

        #endregion
    
        #region Private methods

        private Hashtable ConvertToHashtable(
            ReadOnlyDictionary<string, object> dictionary)
        {
            var returnHashtable = new Hashtable();
            if (dictionary != null)
            {
                foreach (var key in dictionary.Keys)
                {
                    returnHashtable.Add(
                        key: key,
                        value: dictionary[key]);
                }
            }

            return returnHashtable;
        }

        #endregion
    }

    #endregion

    #region AesKey

    internal sealed class AesKey
    {
        #region Properties

        public byte[] Key { get; }
        public byte[] IV { get; }

        #endregion

        #region Constructor

        private AesKey() { }

        public AesKey(
            byte[] key,
            byte[] iv)
        {
            Key = key;
            IV = iv;
        }

        #endregion

        #region Public methods

        public void Clear()
        {
            CryptoUtils.ZeroOutData(Key);
            CryptoUtils.ZeroOutData(IV);
        }

        #endregion
    }

    #endregion

    #region SecureStoreData

    internal sealed class SecureStoreData
    {
        #region Properties

        public AesKey Key { get; set; }
        public byte[] Blob { get; set; }
        public Dictionary<string, SecureStoreMetadata> MetaData { get; set; }

        #endregion

        #region Constructor

        public SecureStoreData()
        {
        }

        public SecureStoreData(
            AesKey key,
            string json,
            byte[] blob)
        {
            Key = key;
            Blob = blob;
            ConvertJsonToMeta(json);
        }

        #endregion
        
        #region Public methods

        // Example of store data as Hashtable
        /*
        @{
            ConfigData =
            @{
                StoreScope='CurrentUser'
                Authentication='Password'
                PasswordTimeout=900
                Interaction='Prompt'
            }
            MetaData =
            @(
                @{Name='TestSecret1'; Type='SecureString'; Offset=14434; Size=5000; Attributes=@{}; AdditionalData=@{}}
                @{Name='TestSecret2'; Type='String'; Offset=34593; Size=5100; Attributes=@{}; AdditionalData=@{}}
                @{Name='TestSecret3'; Type='PSCredential'; Offset=59837; Size=4900; Attributes=@{UserName='UserA'}; AdditionalData=@{Desc='MySecret'}}
                @{Name='TestSecret4'; Type='Hashtable'; Offset=77856; Size=3500; Attributes=@{Element1='SecretElement1'; Element2='SecretElement2'}; AdditionalData=@{}}
            )
        }
        */

        public string ConvertMetaToJson()
        {
            // Meta data array
            var listMetadata = new List<Hashtable>(MetaData.Count);
            foreach (var item in MetaData.Values)
            {
                var metaHashtable = new Hashtable();
                metaHashtable.Add(
                    key: "Name",
                    value: item.Name);
                metaHashtable.Add(
                    key: "Type",
                    value: item.TypeName);
                metaHashtable.Add(
                    key: "Offset",
                    value: item.Offset);
                metaHashtable.Add(
                    key: "Size",
                    value: item.Size);
                metaHashtable.Add(
                    key: "Attributes",
                    value: item.AttributesAsHashtable);
                metaHashtable.Add(
                    key: "AdditionalData",
                    value: item.AdditionalDataAsHashtable);
                
                listMetadata.Add(metaHashtable);
            }
            
            var dataDictionary = new Hashtable();
            dataDictionary.Add(
                key: "MetaData",
                value: listMetadata.ToArray());
            
            return Utils.ConvertHashtableToJson(dataDictionary);
        }

        public void Clear()
        {
            Key.Clear();
            CryptoUtils.ZeroOutData(Blob);
            MetaData?.Clear();
        }

        #endregion

        #region Static methods

        public static SecureStoreData CreateEmpty()
        {
            var data = new SecureStoreData()
            {
                Key = CryptoUtils.GenerateKey(),
                Blob = new byte[0],
                MetaData = new Dictionary<string, SecureStoreMetadata>(StringComparer.InvariantCultureIgnoreCase)
            };

            return data;
        }

        #endregion

        #region Private methods

        // Example meta data json
        /*
        {
            "MetaData": [
            {
                "Name": "TestSecret1",
                "Type": "String",
                "Offset": 34593,
                "Size": 3500,
                "Attributes": {},
                "AdditionalData": {}
            },
            {
                "Name": "TestSecret2",
                "Type": "PSCredential",
                "Offset": 59837,
                "Size": 4200,
                "Attributes": {
                    "UserName": "UserA"
                },
                "AdditionalData": {
                    "Desc": "MySecret"
                }
            }
            ]
        }
        */

        private void ConvertJsonToMeta(string json)
        {
            dynamic data = Utils.ConvertJsonToPSObject(json);

            // Validate
            if (data is null)
            {
                throw new InvalidDataException("Unable to read store json meta data.");
            }

            // Meta data
            dynamic metaDataArray = data.MetaData;
            MetaData = new Dictionary<string, SecureStoreMetadata>(
                metaDataArray.Length,
                StringComparer.CurrentCultureIgnoreCase);
            foreach (var item in metaDataArray)
            {
                var attributesDictionary = new Dictionary<string, object>();
                var attributes = item.Attributes;
                foreach (var prop in ((PSObject)attributes).Properties)
                {
                    attributesDictionary.Add(
                        key: prop.Name,
                        value: prop.Value);
                }

                // Optional additional data.
                var additionalDataDictionary = new Dictionary<string, object>();
                var additionalData = item.AdditionalData;
                if (additionalData != null)
                {
                    foreach (var prop in ((PSObject)additionalData).Properties)
                    {
                        additionalDataDictionary.Add(
                            key: prop.Name,
                            value: prop.Value);
                    }
                }

                MetaData.Add(
                    key: item.Name,
                    value: new SecureStoreMetadata(
                        name: item.Name,
                        typeName: item.Type,
                        offset: (int) item.Offset,
                        size: (int) item.Size,
                        attributes: new ReadOnlyDictionary<string, object>(attributesDictionary),
                        additionalData: new ReadOnlyDictionary<string, object>(additionalDataDictionary)));
            }
        }

        #endregion
    }

    #endregion

    #region SecureStore

    internal sealed class SecureStore : IDisposable
    {
        #region Members

        private SecureString _password;
        private SecureStoreData _data;
        private SecureStoreConfig _configData;
        private Timer _passwordTimer;
        private readonly object _syncObject = new object();
        private static TimeSpan _updateDelay = TimeSpan.FromSeconds(5);

        #endregion

        #region Properties

        public SecureStoreData Data => _data;

        public SecureStoreConfig ConfigData => _configData;

        internal SecureString Password
        {
            get 
            {
                lock (_syncObject)
                {
                    if (ConfigData.PasswordRequired && (_password is null))
                    {
                        throw new PasswordRequiredException(Utils.PasswordRequiredMessage);
                    }

                    var returnPassword = _password?.Copy() ?? null;
                    if (_password != null && _configData.PasswordTimeout == 0)
                    {
                        // PasswordTimeout == 0, means password is only used once.
                        _password = null;
                    }

                    return returnPassword;
                }
            }
        }

        #endregion

        #region Constructor

        public SecureStore(
            SecureStoreData data,
            SecureStoreConfig configData,
            SecureString password = null)
        {
            _data = data;
            _configData = configData;
            SetPassword(password);

            SecureStoreFile.ClearDataUpdateEventList();
            SecureStoreFile.DataUpdated += (sender, args) => HandleDataUpdateEvent(sender, args);

            SecureStoreFile.ClearConfigUpdateEventList();
            SecureStoreFile.ConfigUpdated += (sender, args) => HandleConfigUpdateEvent(sender, args);
        }

        #endregion

        #region Events

        public event EventHandler<EventArgs> StoreConfigUpdated;
        private void RaiseStoreConfigUpdatedEvent()
        {
            if (StoreConfigUpdated != null)
            {
                StoreConfigUpdated.Invoke(this, null);
            }
        }

        #endregion

        #region IDisposable

        public void Dispose()
        {
            _passwordTimer?.Dispose();
            _password?.Clear();
            _data?.Clear();
        }

        #endregion
        
        #region Public methods

        /// <summary>
        /// Sets the current session password, and resets the password timeout.
        /// </summary>
        public void SetPassword(SecureString password)
        {
            if (password != null)
            {
                VerifyPasswordRequired();
            }

            lock (_syncObject)
            {
                _password = password?.Copy();
                if (_password != null)
                {
                    SetPasswordTimer(_configData.PasswordTimeout);
                }
            }
        }

        public void SetPasswordTimer(int timeoutSecs)
        {
            if (_passwordTimer != null)
            {
                _passwordTimer.Dispose();
                _passwordTimer = null;
            }

            if (timeoutSecs > 0)
            {
                _passwordTimer = new Timer(
                    callback: (_) => 
                        { 
                            lock (_syncObject)
                            {
                                _password = null;
                            }
                        },
                    state: null,
                    dueTime: timeoutSecs * 1000,
                    period: Timeout.Infinite);
            }
        }

        /// <summary>
        /// Updates the store password to the new value provided.
        /// Re-encrypts secret data and store file with new password.
        /// </summary>
        public void UpdatePassword(
            SecureString newpassword,
            SecureString oldPassword,
            bool skipPasswordRequiredCheck,
            bool skipConfigFileWrite)
        {
            if (!skipPasswordRequiredCheck)
            {
                VerifyPasswordRequired();
            }

            lock (_syncObject)
            {
                // Verify password.
                if (!SecureStoreFile.ReadFile(
                    oldPassword,
                    out SecureStoreData data,
                    out _))
                {
                    throw new PasswordRequiredException("Unable to access the Microsoft.PowerShell.SecretStore vault with provided oldPassword.");
                }

                // Re-encrypt blob data with new password.
                var newBlob = ReEncryptBlob(
                    newPassword: newpassword,
                    oldPassword: oldPassword,
                    metaData: data.MetaData,
                    key: data.Key,
                    blob: data.Blob,
                    outMetaData: out Dictionary<string, SecureStoreMetadata> newMetaData);

                // Write data to file with new password.
                var newData = new SecureStoreData()
                {
                    Key = data.Key,
                    Blob = newBlob,
                    MetaData = newMetaData
                };

                if (!SecureStoreFile.WriteFile(
                    password: newpassword,
                    data: newData,
                    errorMsg: out string errorMsg))
                {
                    throw new PSInvalidOperationException(
                        string.Format(CultureInfo.InvariantCulture,
                            @"Unable to update password with error: {0}",
                            errorMsg));
                }

                _data = newData;
                SetPassword(newpassword);

                // Password change is considered a configuration change.
                // Induce a configuration change event by writing to the config file.
                if (!skipConfigFileWrite)
                {
                    SecureStoreFile.WriteConfigFile(
                        configData: _configData,
                        out string _);
                }
            }
        }

        public bool WriteBlob(
            string name,
            byte[] blob,
            string typeName,
            Dictionary<string, object> attributes,
            Dictionary<string, object> additionalData,
            SecureString password,
            out string errorMsg)
        {
            if (EnumerateBlobs(
                filter: name,
                metaData: out SecureStoreMetadata[] _,
                out errorMsg))
            {
                return ReplaceBlobImpl(
                    name,
                    blob,
                    typeName,
                    attributes,
                    additionalData,
                    password,
                    out errorMsg);
            }

            return WriteBlobImpl(
                name,
                blob,
                typeName,
                attributes,
                additionalData,
                password,
                out errorMsg);
        }

        public bool ReadBlob(
            string name,
            SecureString password,
            out byte[] blob,
            out SecureStoreMetadata metaData,
            out string errorMsg)
        {
            errorMsg = string.Empty;
            byte[] encryptedBlob = null;
            AesKey key = null;
            lock (_syncObject)
            {
                // Get blob
                if (!_data.MetaData.TryGetValue(
                    key: name,
                    value: out metaData))
                {
                    blob = null;
                    metaData = null;
                    return false;
                }

                key = _data.Key;
                var offset = metaData.Offset;
                var size = metaData.Size;
                encryptedBlob = new byte[size];
                Buffer.BlockCopy(_data.Blob, offset, encryptedBlob, 0, size);
            }
            
            // Decrypt blob
            blob = CryptoUtils.DecryptWithKeyWithRetry(
                passWord: password,
                key: key,
                data: encryptedBlob);

            return true;
        }

        public bool EnumerateBlobs(
            string filter,
            out SecureStoreMetadata[] metaData,
            out string errorMsg)
        {
            errorMsg = string.Empty;
            var filterPattern = new WildcardPattern(
                pattern: filter,
                options: WildcardOptions.IgnoreCase);
            var foundBlobs = new List<SecureStoreMetadata>();

            lock (_syncObject)
            {
                foreach (var key in _data.MetaData.Keys)
                {
                    if (filterPattern.IsMatch(key))
                    {
                        var data = _data.MetaData[key];
                        foundBlobs.Add(
                            new SecureStoreMetadata(data));
                    }
                }
            }

            metaData = foundBlobs.ToArray();
            return (metaData.Length > 0);
        }

        public bool DeleteBlob(
            string name,
            SecureString password,
            out string errorMsg)
        {
            lock (_syncObject)
            {
                if (!_data.MetaData.TryGetValue(
                    key: name,
                    value: out SecureStoreMetadata metaData))
                {
                    errorMsg = string.Format(
                        CultureInfo.InvariantCulture,
                        @"Unable to find item {0} for removal.",
                        name);
                    return false;
                }
                _data.MetaData.Remove(name);

                // Create new blob
                var oldBlob = _data.Blob;
                var offset = metaData.Offset;
                var size = metaData.Size;
                var newSize = (oldBlob.Length - size);
                var newBlob = new byte[newSize];
                Buffer.BlockCopy(oldBlob, 0, newBlob, 0, offset);
                Buffer.BlockCopy(oldBlob, (offset + size), newBlob, offset, (newSize - offset));
                _data.Blob = newBlob;
                CryptoUtils.ZeroOutData(oldBlob);

                // Fix up meta data offsets
                foreach (var metaItem in _data.MetaData.Values)
                {
                    if (metaItem.Offset > offset)
                    {
                        metaItem.Offset -= size;
                    }
                }
            }

            // Write to file
            return SecureStoreFile.WriteFile(
                password: password,
                data: _data,
                out errorMsg);
        }

        public bool UpdateConfigData(
            SecureStoreConfig newConfigData,
            SecureString password,
            PSCmdlet cmdlet,
            out string errorMsg)
        {
            // First update the configuration information.
            SecureStoreConfig oldConfigData;
            lock (_syncObject)
            {
                oldConfigData = _configData;
                _configData = newConfigData;
            }
            if (!SecureStoreFile.WriteConfigFile(
                newConfigData,
                out errorMsg))
            {
                lock(_syncObject)
                {
                    _configData = oldConfigData;
                }

                return false;
            }

            // If password requirement changed, then change password encryption as needed.
            // The user will be prompted for password information only if needed.
            // Password configuration change can be:
            //  1. Password was not required before but now is (new password needed).
            //  2. Password was required before but now is not (old password needed for change).
            if (oldConfigData.PasswordRequired != newConfigData.PasswordRequired)
            {
                bool success;
                try
                {
                    SecureString oldPassword;
                    SecureString newPassword;

                    if (newConfigData.PasswordRequired)
                    {
                        // If a new password is now required and none provided, then prompt for it.
                        oldPassword = null;
                        newPassword = password ?? Utils.PromptForPassword(
                            cmdlet: cmdlet,
                            verifyPassword: true,
                            message: "A password is now required for the local store configuration.\nTo complete the change please provide new password.");
                        
                        if (newPassword is null)
                        {
                            throw new PSInvalidOperationException("New password was not provided.");
                        }
                    }
                    else
                    {
                        // Password is no longer required, but old password is needed to make the change.
                        // If it was not provided, then prompt for it.
                        newPassword = null;
                        oldPassword = password ?? Utils.PromptForPassword(
                            cmdlet: cmdlet,
                            verifyPassword: false,
                            message: "A password is no longer required for the local store configuration.\nTo complete the change please provide the current password.");

                        if (oldPassword is null)
                        {
                            throw new PSInvalidOperationException("Old password was not provided.");
                        }
                    }

                    UpdatePassword(
                        newPassword,
                        oldPassword,
                        skipPasswordRequiredCheck: true,
                        skipConfigFileWrite: true);

                    success = true;
                }
                catch (Exception ex)
                {
                    errorMsg = string.Format(CultureInfo.InvariantCulture,
                        @"Unable to update local store data from configuration change with error: {0}",
                        ex.Message);
                    success = false;
                }

                if (!success)
                {
                    // Attempt to revert back to original configuration.
                    lock(_syncObject)
                    {
                        _configData = oldConfigData;
                    }

                    if (!SecureStoreFile.WriteConfigFile(
                        oldConfigData,
                        out string revertErrorMsg))
                    {
                        errorMsg += string.Format(CultureInfo.InvariantCulture,
                            @"\nUnable to restore local store configuration data with error: {0}",
                            revertErrorMsg);
                    }

                    return false;
                }
            }
            else if ((oldConfigData.PasswordTimeout != newConfigData.PasswordTimeout) && (_password != null))
            {
                SetPasswordTimer(newConfigData.PasswordTimeout);
            }

            errorMsg = string.Empty;
            return true;
        }

        public void UpdateDataFromFile()
        {
            if (SecureStoreFile.ReadFile(
                password: _password,
                data: out SecureStoreData data,
                out string _))
            {
                lock (_syncObject)
                {
                    _data = data;
                }
            }
            
            // If file read fails (e.g., password expired), then skip the update.
        }

        #endregion

        #region Private methods

        private void UpdateConfigFromFile()
        {
            if (!SecureStoreFile.ReadConfigFile(
                configData: out SecureStoreConfig configData,
                out string errorMsg))
            {
                throw new PSInvalidOperationException(errorMsg);
            }

            lock (_syncObject)
            {
                _configData = configData;
            }

            // Refresh secret data
            UpdateDataFromFile();
        }

        private void HandleConfigUpdateEvent(object sender, FileUpdateEventArgs args)
        {
            try
            {
                if ((args.FileChangedTime - SecureStoreFile.LastConfigWriteTime) > _updateDelay)
                {
                    UpdateConfigFromFile();
                }

                RaiseStoreConfigUpdatedEvent();
            }
            catch
            {
            }
        }

        private void HandleDataUpdateEvent(object sender, FileUpdateEventArgs args)
        {
            try
            {
                if ((args.FileChangedTime - SecureStoreFile.LastStoreWriteTime) > _updateDelay)
                {
                    UpdateDataFromFile();
                }
            }
            catch
            {
            }
        }

        private static byte[] ReEncryptBlob(
            SecureString newPassword,
            SecureString oldPassword,
            Dictionary<string, SecureStoreMetadata> metaData,
            AesKey key,
            byte[] blob,
            out Dictionary<string, SecureStoreMetadata> outMetaData)
        {
            if (blob.Length == 0)
            {
                outMetaData = metaData;
                return blob;
            }

            outMetaData = new Dictionary<string, SecureStoreMetadata>(metaData.Count, StringComparer.InvariantCultureIgnoreCase);
            List<byte> newBlobArray = new List<byte>(blob.Length);

            int offset = 0;
            foreach (var metaItem in metaData.Values)
            {
                var oldBlobItem = new byte[metaItem.Size];
                Buffer.BlockCopy(blob, metaItem.Offset, oldBlobItem, 0, metaItem.Size);
                var decryptedBlobItem = CryptoUtils.DecryptWithKeyWithRetry(
                    passWord: oldPassword,
                    key: key,
                    data: oldBlobItem);
                
                byte[] newBlobItem;
                try
                {
                    newBlobItem = CryptoUtils.EncryptWithKey(
                        passWord: newPassword,
                        key: key,
                        data: decryptedBlobItem);
                }
                finally
                {
                    CryptoUtils.ZeroOutData(decryptedBlobItem);
                }

                outMetaData.Add(
                    key: metaItem.Name,
                    value: new SecureStoreMetadata(
                        name: metaItem.Name,
                        typeName: metaItem.TypeName,
                        offset: offset,
                        size: newBlobItem.Length,
                        attributes: metaItem.Attributes,
                        additionalData: metaItem.AdditionalData));
                    
                newBlobArray.AddRange(newBlobItem);

                offset += newBlobItem.Length;
            }

            return newBlobArray.ToArray();
        }

        private bool WriteBlobImpl(
            string name,
            byte[] blob,
            string typeName,
            Dictionary<string, object> attributes,
            Dictionary<string, object> additionalData,
            SecureString password,
            out string errorMsg)
        {
            var newData = new SecureStoreData();
            newData.MetaData = _data.MetaData;
            newData.Key = _data.Key;

            // Encrypt blob
            var blobToWrite = CryptoUtils.EncryptWithKey(
                passWord: password,
                key: _data.Key,
                data: blob);

            lock (_syncObject)
            {
                // Create new store blob
                var oldBlob = _data.Blob;
                var offset = oldBlob.Length;
                var newBlob = new byte[offset + blobToWrite.Length];
                Buffer.BlockCopy(oldBlob, 0, newBlob, 0, offset);
                Buffer.BlockCopy(blobToWrite, 0, newBlob, offset, blobToWrite.Length);
                newData.Blob = newBlob;

                // Create new meta item
                newData.MetaData.Add(
                    key: name,
                    value: new SecureStoreMetadata(
                        name: name,
                        typeName: typeName,
                        offset: offset,
                        size: blobToWrite.Length,
                        attributes: new ReadOnlyDictionary<string, object>(attributes),
                        additionalData: new ReadOnlyDictionary<string, object>(additionalData)));

                // Update store data
                _data = newData;
                CryptoUtils.ZeroOutData(oldBlob);
            }

            // Write to file
            return SecureStoreFile.WriteFile(
                password: password,
                data: _data,
                out errorMsg);
        }

        private bool ReplaceBlobImpl(
            string name,
            byte[] blob,
            string typeName,
            Dictionary<string, object> attributes,
            Dictionary<string, object> additionalData,
            SecureString password,
            out string errorMsg)
        {
            lock (_syncObject)
            {
                // Remove old blob
                if (!DeleteBlob(
                    name: name,
                    password: password,
                    out errorMsg))
                {
                    errorMsg = "Unable to replace existing store item, error: " + errorMsg;
                    return false;
                }

                // Add new blob
                return WriteBlobImpl(
                    name: name,
                    blob: blob,
                    typeName: typeName,
                    attributes: attributes,
                    additionalData: additionalData,
                    password: password,
                    out errorMsg);
            }
        }

        private void VerifyPasswordRequired()
        {
            if (!_configData.PasswordRequired)
            {
                throw new PSInvalidOperationException(
                    "The local store is not configured to use a password.");
            }
        }

        #endregion

        #region Static methods

        private static SecureStore GetDefault(
            SecureStoreConfig configData)
        {
            var data = SecureStoreData.CreateEmpty();

            return new SecureStore(
                data: data,
                configData: configData);
        }

        public static SecureStore GetStore(
            SecureString password)
        {
            // Read config from file.
            SecureStoreConfig configData;
            if (!SecureStoreFile.ReadConfigFile(
                configData: out configData,
                errorMsg: out string errorMsg))
            {
                if (errorMsg.Equals("NoConfigFile", StringComparison.OrdinalIgnoreCase))
                {
                    if (SecureStoreFile.StoreFileExists())
                    {
                        // This indicates a corrupted store configuration or inadvertent file deletion.
                        // settings needed for store, or must re-create local store.
                        throw new InvalidOperationException("Secure local store is in inconsistent state.");
                    }

                    // First time, use default configuration.
                    configData = SecureStoreConfig.GetDefault();
                    if (!SecureStoreFile.WriteConfigFile(
                        configData,
                        out errorMsg))
                    {
                        throw new PSInvalidOperationException(errorMsg);
                    }
                }
            }
            
            // Enforce required password configuration.
            if (configData.PasswordRequired && (password is null))
            {
                throw new PasswordRequiredException(Utils.PasswordRequiredMessage);
            }

            // Check password configuration consistency.
            if ((password != null) && !configData.PasswordRequired)
            {
                throw new PSInvalidOperationException(
                    "The local store is not configured to use a password. First change the store configuration to require a password.");
            }

            // Read store from file.
            if (SecureStoreFile.ReadFile(
                password: password,
                data: out SecureStoreData data,
                out errorMsg))
            {
                return new SecureStore(
                    data: data, 
                    configData: configData,
                    password: password);
            }

            // If no file, create a default store
            if (errorMsg.Equals("NoFile", StringComparison.OrdinalIgnoreCase))
            {
                var secureStore = GetDefault(configData);
                if (!SecureStoreFile.WriteFile(
                    password: password,
                    data: secureStore.Data,
                    out errorMsg))
                {
                    throw new PSInvalidOperationException(
                        string.Format(CultureInfo.InvariantCulture, 
                        @"Unable to write store data to file with error: {0}", errorMsg));
                }

                secureStore.SetPassword(password);
                return secureStore;
            }

            throw new PSInvalidOperationException(errorMsg);
        }

        #endregion
    }

    #endregion

    #region SecureStoreFile

    internal static class SecureStoreFile
    {
        #region Members

        private const string StoreFileName = "storefile";
        private const string StoreConfigName = "storeconfig";
        private const string StoreKeyFileName = "storeaux";

        private static readonly string LocalStoreFilePath;
        private static readonly string LocalConfigFilePath;
        private static readonly string LocalKeyFilePath;

        private static readonly FileSystemWatcher _storeFileWatcher;
        private static readonly Timer _updateEventTimer;
        private static readonly object _syncObject;
        private static DateTime _lastConfigWriteTime;
        private static DateTime _lastStoreWriteTime;
        private static DateTime _lastStoreFileChange;
        private static readonly bool _isLocationPathValid;

        #endregion

        #region Constructor

        static SecureStoreFile()
        {
            _syncObject = new object();

            string locationPath;
            string secretManagementLocalPath;
            if (Utils.IsWindows)
            {
                locationPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                secretManagementLocalPath = Path.Combine(locationPath, "Microsoft", "PowerShell", "secretmanagement");
            }
            else
            {
                locationPath = Environment.GetEnvironmentVariable("HOME");
                secretManagementLocalPath = Path.Combine(locationPath, ".secretmanagement");
            }

            _isLocationPathValid = !string.IsNullOrEmpty(locationPath);
            if (!_isLocationPathValid)
            {
                // File location path can be invalid for some Windows built-in account scenarios.
                // Surface the error later when not initializing a type.
                return;
            }

            var localStorePath = Path.Combine(secretManagementLocalPath, "localstore");
            LocalStoreFilePath = Path.Combine(localStorePath, StoreFileName);
            LocalConfigFilePath = Path.Combine(localStorePath, StoreConfigName);
            LocalKeyFilePath = Path.Combine(localStorePath, StoreKeyFileName);

            if (!Directory.Exists(localStorePath))
            {
                Directory.CreateDirectory(localStorePath);

                if (Utils.IsWindows)
                {
                    SetDirectoryACLs(localStorePath);
                }
                else
                {
                    SetFilePermissions(
                        filePath: localStorePath,
                        isDirectory: true);
                }
            }

            _storeFileWatcher = new FileSystemWatcher(localStorePath);
            _storeFileWatcher.NotifyFilter = NotifyFilters.LastWrite;
            _storeFileWatcher.Filter = "store*";    // storefile, storeconfig
            _storeFileWatcher.EnableRaisingEvents = true;
            _storeFileWatcher.Changed += (sender, args) => { UpdateData(args); };

            _lastConfigWriteTime = DateTime.MinValue;
            _lastStoreWriteTime = DateTime.MinValue;
            _updateEventTimer = new Timer(
                (state) => {
                    try
                    {
                        DateTime fileChangeTime;
                        lock (_syncObject)
                        {
                            fileChangeTime = _lastStoreFileChange;
                        }

                        RaiseDataUpdatedEvent(
                            new FileUpdateEventArgs(fileChangeTime));
                    }
                    catch
                    {
                    }
                });
        }

        #endregion

        #region Events

        public static event EventHandler<FileUpdateEventArgs> DataUpdated;
        private static void RaiseDataUpdatedEvent(FileUpdateEventArgs args)
        {
            if (DataUpdated != null)
            {
                DataUpdated.Invoke(null, args);
            }
        }
        public static void ClearDataUpdateEventList()
        {
            if (DataUpdated != null)
            {
                foreach (var handlerDelegate in DataUpdated.GetInvocationList())
                {
                    DataUpdated -= (EventHandler<FileUpdateEventArgs>) handlerDelegate;
                }
            }
        }

        public static event EventHandler<FileUpdateEventArgs> ConfigUpdated;
        private static void RaiseConfigUpdatedEvent(FileUpdateEventArgs args)
        {
            if (ConfigUpdated != null)
            {
                ConfigUpdated.Invoke(null, args);
            }
        }
        public static void ClearConfigUpdateEventList()
        {
            if (ConfigUpdated != null)
            {
                foreach (var handlerDelegate in ConfigUpdated.GetInvocationList())
                {
                    ConfigUpdated -= (EventHandler<FileUpdateEventArgs>) handlerDelegate;
                }
            }
        }

        #endregion

        #region Enums

        public enum PasswordConfiguration
        {
            NoFileDefaultRequired = 0,
            Required = 1,
            NotRequired = 2
        }

        #endregion

        #region Properties

        public static DateTime LastConfigWriteTime
        {
            get
            {
                lock (_syncObject)
                {
                    return _lastConfigWriteTime;
                }
            }
        }

        public static DateTime LastStoreWriteTime
        {
            get
            {
                lock (_syncObject)
                {
                    return _lastStoreWriteTime;
                }
            }
        }

        public static bool ConfigAllowsPrompting
        {
            get
            {
                // Try to read the local store configuration file.
                if (ReadConfigFile(
                    configData: out SecureStoreConfig configData,
                    out string _))
                {
                    return configData.Interaction == Interaction.Prompt;
                }

                // Default behavior is to allow password prompting.
                return true;
            }
        }

        public static PasswordConfiguration ConfigRequiresPassword
        {
            get
            {
                // Try to read the local store configuration file.
                if (ReadConfigFile(
                    configData: out SecureStoreConfig configData,
                    out string _))
                {
                    return (configData.Authentication == Authenticate.Password) ? PasswordConfiguration.Required : PasswordConfiguration.NotRequired;
                }

                // Password is required by default.
                return PasswordConfiguration.NoFileDefaultRequired;
            }
        }

        #endregion
        
        #region Public methods

        // Data file structure
        /*
        int:    data hash size
        byte[]: data hash
        <Data>
        int:    json blob size
        byte[]: json blob
        byte[]: data blob
        </Data>
        */

        public static bool WriteFile(
            SecureString password,
            SecureStoreData data,
            out string errorMsg)
        {
            CheckFilePath();

            // Encrypt json meta data.
            var jsonStr = data.ConvertMetaToJson();
            var jsonBlob = CryptoUtils.EncryptWithKey(
                passWord: password,
                key: data.Key,
                data: Encoding.UTF8.GetBytes(jsonStr));

            // Create single file data blob.
            var intSize = sizeof(Int32);
            var jsonBlobSize = jsonBlob.Length;
            var fileDataBlobSize = intSize + jsonBlobSize + data.Blob.Length;
            var fileDataBlob = new byte[fileDataBlobSize];
            var index = 0;
            
            // Copy json blob size.
            Buffer.BlockCopy(
                src: BitConverter.GetBytes(jsonBlobSize),
                srcOffset: 0,
                dst: fileDataBlob,
                dstOffset: index,
                count: intSize);
            index += intSize;

            // Copy json blob.
            Buffer.BlockCopy(
                src: jsonBlob,
                srcOffset: 0,
                dst: fileDataBlob,
                dstOffset: index,
                count: jsonBlobSize);
            index += jsonBlobSize;

            // Copy data blob.
            Buffer.BlockCopy(
                src: data.Blob,
                srcOffset: 0,
                dst: fileDataBlob,
                dstOffset: index,
                count: data.Blob.Length);

            // Compute hash.
            var dataHash = CryptoUtils.ComputeHashWithPasswordOrUser(
                passWord: password,
                dataToHash: fileDataBlob);

            var count = 0;
            Exception exFail = null;
            do
            {
                try
                {
                    if (!Utils.IsWindows && !File.Exists(LocalKeyFilePath))
                    {
                        // Non-Windows platform file permissions must be set individually.
                        // Windows platform file ACLs are inherited from containing directory.
                        using (File.Create(LocalKeyFilePath)) { }
                        SetFilePermissions(
                            filePath: LocalKeyFilePath,
                            isDirectory: false);
                    }

                    if (!Utils.IsWindows && !File.Exists(LocalStoreFilePath))
                    {
                        // Non-Windows platform file permissions must be set individually.
                        // Windows platform file ACLs are inherited from containing directory.
                        using (File.Create(LocalStoreFilePath)) { }
                        SetFilePermissions(
                            filePath: LocalStoreFilePath,
                            isDirectory: false);
                    }

                    // Write to file.
                    using (var fileStream = File.OpenWrite(LocalStoreFilePath))
                    using (var keyFileStream = File.OpenWrite(LocalKeyFilePath))
                    {
                        // Write to keyfile.
                        WriteKeyFile(
                            fs: keyFileStream,
                            key: data.Key);

                        // Write to datafile.
                        fileStream.Seek(0, 0);

                        // Write hash length and hash to file.
                        fileStream.Write(
                            array: BitConverter.GetBytes(dataHash.Length),
                            offset: 0,
                            count: intSize);
                        fileStream.Write(
                            array: dataHash,
                            offset: 0,
                            count: dataHash.Length);
                        
                        // Write data blob to file.
                        fileStream.Write(
                            array: fileDataBlob,
                            offset: 0,
                            count: fileDataBlob.Length);

                        if (fileStream.Position != fileStream.Length)
                        {
                            fileStream.SetLength(fileStream.Position);
                        }

                        lock (_syncObject)
                        {
                            _lastStoreWriteTime = DateTime.Now;
                        }

                        errorMsg = string.Empty;
                        return true;
                    }
                }
                catch (IOException exIO)
                {
                    // Make up to four attempts.
                    exFail = exIO;
                }
                catch (Exception ex)
                {
                    // Unexpected error.
                    exFail = ex;
                    break;
                }

                System.Threading.Thread.Sleep(250);
            } while (++count < 4);

            errorMsg = string.Format(
                CultureInfo.InvariantCulture,
                @"Unable to write to local store file with error: {0}",
                exFail.Message);

            return false;
        }

        public static bool ReadFile(
            SecureString password,
            out SecureStoreData data,
            out string errorMsg)
        {
            CheckFilePath();

            data = null;

            if (!File.Exists(LocalStoreFilePath))
            {
                errorMsg = "NoFile";
                return false;
            }

            // Read encryption key from file.
            if (!ReadKeyFile(
                key: out AesKey key,
                errorMsg: out errorMsg))
            {
                return false;
            }

            // Open and read from file stream
            var intSize = sizeof(Int32);
            byte[] intField = new byte[intSize];
            byte[] hash = null;
            byte[] fileDataBlob = null;

            var count = 0;
            Exception exFail = null;
            do
            {
                try
                {
                    using (var fileStream = File.OpenRead(LocalStoreFilePath))
                    {
                        // Read file data hash.
                        fileStream.Read(intField, 0, intSize);
                        var hashSize = BitConverter.ToInt32(intField, 0);
                        hash = new byte[hashSize];
                        fileStream.Read(hash, 0, hashSize);

                        // Read file data blob.
                        var fileDataBlobSize = (int) (fileStream.Length - (intSize + hashSize));
                        fileDataBlob = new byte[fileDataBlobSize];
                        fileStream.Read(fileDataBlob, 0, fileDataBlobSize);

                        break;
                    }
                }
                catch (IOException exIO)
                {
                    // Make up to four attempts.
                    exFail = exIO;
                }
                catch (Exception ex)
                {
                    // Unexpected error.
                    exFail = ex;
                    break;
                }

                System.Threading.Thread.Sleep(250);

            } while (++count < 4);

            if (hash is null || fileDataBlob is null)
            {
                errorMsg = string.Format(
                    CultureInfo.InvariantCulture,
                    @"Unable to read from local store file with error: {0}",
                    exFail?.Message ?? string.Empty);

                return false;
            }

            // Validate file data blob integrity.
            if (!CryptoUtils.ValidateHashWithPasswordOrUser(
                passWord: password,
                hash: hash,
                dataToValidate: fileDataBlob))
            {
                errorMsg = "Store file integrity check failed.\nThe provided password may be invalid, or store files have become corrupted or have been tampered with.";
                return false;
            }

            // Extract json blob size.
            var index = 0;
            Buffer.BlockCopy(
                src: fileDataBlob,
                srcOffset: index,
                dst: intField,
                dstOffset: 0,
                count: intSize);
            index += intSize;
            var jsonBlobSize = BitConverter.ToInt32(intField, 0);

            // Extract json blob and decrypt.
            var jsonBlob = new byte[jsonBlobSize];
            Buffer.BlockCopy(
                src: fileDataBlob,
                srcOffset: index,
                dst: jsonBlob,
                dstOffset: 0,
                count: jsonBlobSize);
            index += jsonBlobSize;

            var jsonStr = Encoding.UTF8.GetString(
                CryptoUtils.DecryptWithKeyWithRetry(
                    passWord: password,
                    key: key,
                    data: jsonBlob));

            // Extract data blob.
            var dataBlobSize = (fileDataBlob.Length - (jsonBlobSize + intSize));
            var dataBlob = new byte[dataBlobSize];
            Buffer.BlockCopy(
                src: fileDataBlob,
                srcOffset: index,
                dst: dataBlob,
                dstOffset: 0,
                count: dataBlobSize);

            data = new SecureStoreData(
                key: key,
                json: jsonStr,
                blob: dataBlob);

            errorMsg = string.Empty;
            return true;
        }

        public static bool WriteConfigFile(
            SecureStoreConfig configData,
            out string errorMsg)
        {
            CheckFilePath();

            // Encrypt config json data.
            var jsonStr = configData.ConvertToJson();
            var encryptKey = CryptoUtils.GenerateKeyFromUserName();
            var jsonEncrypted = CryptoUtils.EncryptWithKey(
                passWord: null,
                key: encryptKey,
                Encoding.UTF8.GetBytes(jsonStr));
            encryptKey.Clear();

            var count = 0;
            Exception exFail = null;
            do
            {
                try
                {
                    if (!Utils.IsWindows && !File.Exists(LocalConfigFilePath))
                    {
                        // Non-Windows platform file permissions must be set individually.
                        // Windows platform file ACLs are inherited from containing directory.
                        using (File.Create(LocalConfigFilePath)) { }
                        SetFilePermissions(
                            filePath: LocalConfigFilePath,
                            isDirectory: false);
                    }

                    File.WriteAllBytes(
                        path: LocalConfigFilePath,
                        bytes: jsonEncrypted);

                    lock (_syncObject)
                    {
                        _lastConfigWriteTime = DateTime.Now;
                    }
                
                    errorMsg = string.Empty;
                    return true;
                }
                catch (IOException exIO)
                {
                    // Make up to four attempts.
                    exFail = exIO;
                }
                catch (Exception ex)
                {
                    // Unexpected error.
                    exFail = ex;
                    break;
                }

                System.Threading.Thread.Sleep(250);
            } while (++count < 4);

            errorMsg = string.Format(
                CultureInfo.InvariantCulture,
                @"Unable to write to local configuration file with error: {0}",
                exFail.Message);

            return false;
        }

        public static bool ReadConfigFile(
            out SecureStoreConfig configData,
            out string errorMsg)
        {
            CheckFilePath();

            configData = null;

            if ((!File.Exists(LocalConfigFilePath)))
            {
                errorMsg = "NoConfigFile";
                return false;
            }

            // Open and read from file stream.
            byte[] encryptedConfigJson = null;
            var count = 0;
            Exception exFail = null;
            do
            {
                try
                {
                    encryptedConfigJson = File.ReadAllBytes(LocalConfigFilePath);
                    break;
                }
                catch (IOException exIO)
                {
                    // Make up to four attempts.
                    exFail = exIO;
                }
                catch (Exception ex)
                {
                    // Unexpected error.
                    exFail = ex;
                    break;
                }

                System.Threading.Thread.Sleep(250);
            } while (++count < 4);

            if (encryptedConfigJson is null)
            {
                errorMsg = string.Format(
                    CultureInfo.InvariantCulture,
                    @"Unable to read from local store configuration file with error: {0}",
                    exFail?.Message ?? string.Empty);

                return false;
            }

            // Decrypt config json data.
            var configJsonBlob = CryptoUtils.DecryptWithNoKeyWithRetry(
                data: encryptedConfigJson);

            var configJson = Encoding.UTF8.GetString(configJsonBlob);
            configData = new SecureStoreConfig(configJson);
            errorMsg = string.Empty;
            return true;
        }

        public static bool RemoveStoreFile(out string errorMsg)
        {
            CheckFilePath();

            var count = 0;
            Exception exFail = null;
            do
            {
                try
                {
                    File.Delete(LocalStoreFilePath);
                    errorMsg = string.Empty;
                    return true;
                }
                catch (IOException exIO)
                {
                    // Make up to four attempts.
                    exFail = exIO;
                }
                catch (Exception ex)
                {
                    // Unexpected error.
                    exFail = ex;
                    break;
                }

                System.Threading.Thread.Sleep(250);
            } while (++count < 4);

            errorMsg = string.Format(
                CultureInfo.InvariantCulture,
                @"Unable to remove the local store file with error: {0}",
                exFail.Message);

            return false;
        }

        public static bool StoreFileExists()
        {
            return File.Exists(LocalStoreFilePath);
        }

        #endregion

        #region Private methods

        // Key file structure
        /*
        int:    key blob size
        int:    iv blob size
        byte[]: key blob
        byte[]: iv blob
        */

        private static void WriteKeyFile(
            FileStream fs,
            AesKey key)
        {
            fs.Seek(0, 0);

            // Create file data blob.
            var intSize = sizeof(Int32);
            var keyBlobSize = key.Key.Length;
            var ivBlobSize = key.IV.Length;
            var fileDataBlobSize = (intSize * 2) + keyBlobSize + ivBlobSize;
            var fileDataBlob = new byte[fileDataBlobSize];
            var index = 0;

            // Copy key size.
            Buffer.BlockCopy(
                src: BitConverter.GetBytes(keyBlobSize),
                srcOffset: 0,
                dst: fileDataBlob,
                dstOffset: index,
                count: intSize);
            index += intSize;

            // Copy iv size.
            Buffer.BlockCopy(
                src: BitConverter.GetBytes(ivBlobSize),
                srcOffset: 0,
                dst: fileDataBlob,
                dstOffset: index,
                count: intSize);
            index += intSize;

            // Copy key blob.
            Buffer.BlockCopy(
                src: key.Key,
                srcOffset: 0,
                dst: fileDataBlob,
                dstOffset: index,
                count: keyBlobSize);
            index += keyBlobSize;

            // Copy iv blob.
            Buffer.BlockCopy(
                src: key.IV,
                srcOffset: 0,
                dst: fileDataBlob,
                dstOffset: index,
                count: ivBlobSize);
            index += ivBlobSize;

            // Encrypt with Username.
            var fileEncryptKey = CryptoUtils.GenerateKeyFromUserName();
            var encryptedData = CryptoUtils.EncryptWithKey(
                passWord: null,
                key: fileEncryptKey,
                fileDataBlob);
            fileEncryptKey.Clear();

            // Write to file.
            fs.Write(
                array: encryptedData,
                offset: 0,
                count: encryptedData.Length);
        }

        private static bool ReadKeyFile(
            out AesKey key,
            out string errorMsg)
        {
            key = null;
            byte[] encryptedDataBlob = null;
            var count = 0;
            Exception exFail = null;
            do
            {
                try
                {
                    // Open and read encrypted data from file.
                    encryptedDataBlob = File.ReadAllBytes(LocalKeyFilePath);
                    break;
                }
                catch (IOException exIO)
                {
                    // Make up to four attempts.
                    exFail = exIO;
                }
                catch (Exception ex)
                {
                    // Unexpected error.
                    exFail = ex;
                    break;
                }

                System.Threading.Thread.Sleep(250);
            } while (++count < 4);

            if (encryptedDataBlob is null)
            {
                errorMsg = string.Format(
                    CultureInfo.InvariantCulture,
                    @"Unable to read from local key file with error: {0}",
                    exFail?.Message ?? string.Empty);

                return false;
            }

            // Decrypt data.
            var dataBlob = CryptoUtils.DecryptWithNoKeyWithRetry(
                data: encryptedDataBlob);

            var intSize = sizeof(Int32);
            byte[] intField = new byte[intSize];

            // Extract key blob size.
            var index = 0;
            Buffer.BlockCopy(
                src: dataBlob,
                srcOffset: index,
                dst: intField,
                dstOffset: 0,
                count: intSize);
            index += intSize;
            var keyBlobSize = BitConverter.ToInt32(intField, 0);

            // Extract iv blob size.
            Buffer.BlockCopy(
                src: dataBlob,
                srcOffset: index,
                dst: intField,
                dstOffset: 0,
                count: intSize);
            index += intSize;
            var ivBlobSize = BitConverter.ToInt32(intField, 0);

            // Extract key blob
            var keyBlob = new byte[keyBlobSize];
            Buffer.BlockCopy(
                src: dataBlob,
                srcOffset: index,
                dst: keyBlob,
                dstOffset: 0,
                count: keyBlobSize);
            index += keyBlobSize;

            // Extract iv blob
            var ivBlob = new byte[ivBlobSize];
            Buffer.BlockCopy(
                src: dataBlob,
                srcOffset: index,
                dst: ivBlob,
                dstOffset: 0,
                count: ivBlobSize);
            index += ivBlobSize;

            key = new AesKey(keyBlob, ivBlob);
            errorMsg = string.Empty;
            return true;
        }

        private static void UpdateData(FileSystemEventArgs args)
        {
            try
            {
                var lastFileChange = System.IO.File.GetLastWriteTime(args.FullPath);
                var fileName = System.IO.Path.GetFileNameWithoutExtension(args.FullPath);
                if (fileName.Equals(StoreFileName))
                {
                    lock (_syncObject)
                    {
                        // Set/reset event callback timer for each file change event.
                        // This is to smooth out multiple file changes into a single update event.
                        _lastStoreFileChange = lastFileChange;
                        _updateEventTimer.Change(
                            dueTime: 5000,              // 5 second delay
                            period: Timeout.Infinite);
                    }
                }
                else if (fileName.Equals(StoreConfigName))
                {
                    RaiseConfigUpdatedEvent(
                        new FileUpdateEventArgs(lastFileChange));
                }
            }
            catch
            {
            }
        }

        private static void SetDirectoryACLs(string directoryPath)
        {
            // Windows platform.

            // For Windows, file permissions are set to FullAccess for current user account only.
            // SetAccessRule method applies to this directory.
            var dirSecurity = new DirectorySecurity();
            dirSecurity.SetAccessRule(
                new FileSystemAccessRule(
                    identity: WindowsIdentity.GetCurrent().User,
                    type: AccessControlType.Allow,
                    fileSystemRights: FileSystemRights.FullControl,
                    inheritanceFlags: InheritanceFlags.None,
                    propagationFlags: PropagationFlags.None));

            // AddAccessRule method applies to child directories and files.
            dirSecurity.AddAccessRule(
                new FileSystemAccessRule(
                identity: WindowsIdentity.GetCurrent().User,
                fileSystemRights: FileSystemRights.FullControl,
                type: AccessControlType.Allow,
                inheritanceFlags: InheritanceFlags.ObjectInherit | InheritanceFlags.ContainerInherit,
                propagationFlags: PropagationFlags.InheritOnly));

            // Set access rule protections.
            dirSecurity.SetAccessRuleProtection(
                isProtected: true,
                preserveInheritance: false);

            // Set directory owner.
            dirSecurity.SetOwner(WindowsIdentity.GetCurrent().User);

            // Apply new rules.
            System.IO.FileSystemAclExtensions.SetAccessControl(
                directoryInfo: new DirectoryInfo(directoryPath),
                directorySecurity: dirSecurity);
        }

        private static void SetFilePermissions(
            string filePath,
            bool isDirectory)
        {
            // Non-Windows platforms.

            // Set directory permissions to current user only.
            /*
            Current user is user owner.
            Current user is group owner.
            Permission for user dir owner:      rwx    (execute for directories only)
            Permission for user file owner:     rw-    (no file execute)
            Permissions for group owner:        ---    (no access)
            Permissions for others:             ---    (no access)
            */
            var script = isDirectory ? 
                string.Format(CultureInfo.InvariantCulture, @"chmod u=rwx,g=---,o=--- {0}", filePath) :
                string.Format(CultureInfo.InvariantCulture, @"chmod u=rw-,g=---,o=--- {0}", filePath);
            PowerShellInvoker.InvokeScriptCommon<PSObject>(
                script: script,
                args: new object[0] ,
                error: out ErrorRecord error);
        }

        /*
        private const string s_permissionsWarningMessage = "Store access rules have been modified.";
        // TODO: CheckFileACLs, CheckFilePermissions
        private static bool CheckDirectoryACLs(
            string directoryPath,
            out string warningMessage)
        {
            // Windows platform.
            var dirInfo = new DirectoryInfo(directoryPath);
            var dirAccessRules = dirInfo.GetAccessControl().GetAccessRules(
                includeExplicit: true,
                includeInherited: false,
                targetType: typeof(SecurityIdentifier));

            if (dirAccessRules.Count > 1)
            {
                warningMessage = s_permissionsWarningMessage;
                return false;
            }

            var rule = dirAccessRules[0];

            if (rule.IsInherited ||
                rule.IdentityReference != WindowsIdentity.GetCurrent().User ||
                !rule.InheritanceFlags.HasFlag(InheritanceFlags.ContainerInherit) ||
                !rule.InheritanceFlags.HasFlag(InheritanceFlags.ObjectInherit) ||
                rule.PropagationFlags != PropagationFlags.None)
            {
                warningMessage = s_permissionsWarningMessage;
                return false;
            }

            warningMessage = string.Empty;
            return true;
        }

        private static bool CheckDirectoryPermissions(
            string directoryPath,
            out string warningMessage)
        {
            // TODO:
            warningMessage = "Not yet supported.";
            return false;
        }
        */

        private static void CheckFilePath()
        {
            if (!_isLocationPathValid)
            {
                var msg = Utils.IsWindows ? 
                            "Unable to find a Local Application Data folder location for the current user, which is needed to store vault information for this configuration scope.\nWindows built-in accounts do not provide the Location Application Data folder and are not currently supported for this configuration scope." :
                            "Unable to find a 'HOME' path location for the current user, which is needed to store vault information for this configuration scope.";
                throw new InvalidOperationException(msg);
            }
        }

        #endregion
    }

    #endregion

    #region Event args

    internal sealed class FileUpdateEventArgs : EventArgs
    {
        public DateTime FileChangedTime
        {
            get;
        }

        public FileUpdateEventArgs(DateTime fileChangedTime)
        {
            FileChangedTime = fileChangedTime;
        }
    }

    #endregion

    #endregion

    #region PowerShellInvoker

    internal static class PowerShellInvoker
    {
        #region Members

        private static System.Management.Automation.PowerShell _powershell = 
            System.Management.Automation.PowerShell.Create(RunspaceMode.NewRunspace);

        #endregion

        #region Methods

        public static Collection<T> InvokeScriptCommon<T>(
            string script,
            object[] args,
            out ErrorRecord error)
        {
            Collection<T> results;
            try
            {
                results = _powershell.AddScript(script).AddParameters(args).Invoke<T>();
                error = (_powershell.Streams.Error.Count > 0) ? _powershell.Streams.Error[0] : null;
            }
            catch (Exception ex)
            {
                error = new ErrorRecord(
                    exception: ex,
                    errorId: "PowerShellInvokerInvalidOperation",
                    errorCategory: ErrorCategory.InvalidOperation,
                    targetObject: null);
                results = new Collection<T>();
            }
            finally
            {
                _powershell.Commands.Clear();
            }

            return results;
        }

        #endregion
    }

    #endregion

    #region LocalSecretStore

    /// <summary>
    /// Local secret store
    /// </summary>
    public sealed class LocalSecretStore : IDisposable
    {
        #region Members

        private const string PSHashtableTag = "psht:";
        private const string ByteArrayType = "ByteArrayType";
        private const string StringType = "StringType";
        private const string SecureStringType = "SecureStringType";
        private const string PSCredentialType = "CredentialType";
        private const string HashtableType = "HashtableType";
        private const string VaultPaswordPrompt = "Vault {0} requires a password.";
        private const string NewVaultPasswordPrompt = "Creating a new {0} vault. A password is required by the current store configuration.";
        private const int MaxHashtableItemCount = 20;

        private readonly SecureStore _secureStore;

        private static object SyncObject;
        private static LocalSecretStore LocalStore;
        private static Dictionary<string, object> DefaultTag;
        private static Dictionary<string, object> EmptyMetadata;

        #endregion

        #region Properties

        internal SecureStoreConfig Configuration
        {
            get => new SecureStoreConfig(
                        scope: _secureStore.ConfigData.Scope,
                        authentication: _secureStore.ConfigData.Authentication,
                        passwordTimeout: _secureStore.ConfigData.PasswordTimeout,
                        interaction: _secureStore.ConfigData.Interaction);
        }

        public static bool AllowPrompting
        {
            get => SecureStoreFile.ConfigAllowsPrompting;
        }

        internal static SecureStoreFile.PasswordConfiguration PasswordRequired
        {
            get => SecureStoreFile.ConfigRequiresPassword;
        }

        #endregion
        
        #region Constructor

        private LocalSecretStore()
        {
        }

        internal LocalSecretStore(
            SecureStore secureStore)
        {
            _secureStore = secureStore;
            _secureStore.StoreConfigUpdated += (sender, args) => {
                // If the local store configuration changed, then reload the store from file.
                LocalSecretStore.Reset();
            };
        }

        static LocalSecretStore()
        {
            SyncObject = new object();

            DefaultTag = new Dictionary<string, object>()
                {
                    { "Tag", "PSItem" }
                };

            EmptyMetadata = new Dictionary<string, object>();
        }

        #endregion
    
        #region IDisposable

        public void Dispose()
        {
            _secureStore?.Dispose();
        }

        #endregion

        #region Public static

        public static LocalSecretStore GetInstance(
            SecureString password = null,
            PSCmdlet cmdlet = null)
        {
            if (password != null)
            {
                Reset();
            }

            if (LocalStore is null)
            {
                lock (SyncObject)
                {
                    if (LocalStore is null)
                    {
                        try
                        {
                            LocalStore = new LocalSecretStore(
                                SecureStore.GetStore(password));
                        }
                        catch (PasswordRequiredException)
                        {
                            if (password != null)
                            {
                                throw new PasswordRequiredException("The provided password is incorrect for the Microsoft.PowerShell.SecretStore module vault.");
                            }

                            if (cmdlet != null && AllowPrompting)
                            {
                                password = PromptForPassword(
                                    vaultName: "Microsoft.PowerShell.SecretStore",
                                    cmdlet: cmdlet);

                                LocalStore = new LocalSecretStore(
                                    SecureStore.GetStore(password));

                                return LocalStore;
                            }

                            throw;
                        }
                    }
                }
            }

            return LocalStore;
        }

        public static void PromptAndUnlockVault(
            string vaultName,
            PSCmdlet cmdlet)
        {
            var password = PromptForPassword(vaultName, cmdlet);
            LocalSecretStore.GetInstance(password).UnlockLocalStore(password);
        }

        public static bool UnlockVault(
            SecureString password,
            out string errorMsg)
        {
            try
            {
                LocalSecretStore.GetInstance(password).UnlockLocalStore(password);
                errorMsg = string.Empty;
                return true;
            }
            catch (Exception ex)
            {
                errorMsg = ex.Message;
                return false;
            }
        }

        #endregion
        
        #region Public methods

        public bool WriteMetadata(
            string name,
            Hashtable metadata,
            out string errorMsg)
        {
            if (!ReadObject(
                name: name,
                out object outObject,
                out string readErrorMsg))
            {
                errorMsg = string.Format(CultureInfo.InvariantCulture,
                    "Microsoft.PowerShell.SecretStore vault cannot write metadata to {0} because the secret does not exist.",
                    name);
                return false;
            }

            if (!WriteObject(
                name: name,
                objectToWrite: outObject,
                metadata: metadata,
                out string writeErrorMsg))
            {
                errorMsg = string.Format(CultureInfo.InvariantCulture,
                    "Microsoft.PowerShell.SecretStore vault cannot write metadata to {0} with error message: {1}",
                    name,
                    readErrorMsg);
                return false;
            }

            errorMsg = string.Empty;
            return true;
        }

        public bool WriteObject<T>(
            string name,
            T objectToWrite,
            out string errorMsg)
        {
            return WriteObject(
                name: name,
                objectToWrite: objectToWrite,
                metadata: null,
                out errorMsg);
        }

        public bool WriteObject<T>(
            string name,
            T objectToWrite,
            Hashtable metadata,
            out string errorMsg)
        {
            var password = _secureStore.Password;
            try
            {
                return WriteObjectImpl(
                    name,
                    objectToWrite,
                    metadata,
                    password,
                    out errorMsg);
            }
            finally
            {
                password?.Clear();
            }
        }

        public bool ReadObject(
            string name,
            out object outObject,
            out string errorMsg)
        {
            var password = _secureStore.Password;
            try
            {
                return ReadObjectImpl(
                    name,
                    password,
                    out outObject,
                    out errorMsg);
            }
            finally
            {
                password?.Clear();
            }
        }

        public bool DeleteObject(
            string name,
            out string errorMsg)
        {
            var password = _secureStore.Password;

            try
            {
                if (!ReadObjectImpl(
                    name,
                    password,
                    out object outObject,
                    out errorMsg))
                {
                    return false;
                }

                switch (outObject)
                {
                    case Hashtable hashtable:
                        return DeleteHashtable(
                            name,
                            password,
                            out errorMsg);

                    default:
                        return DeleteBlob(
                            name,
                            password,
                            out errorMsg);
                }
            }
            finally
            {
                password?.Clear();
            }
        }

        public bool EnumerateObjectInfo(
            string filter,
            out SecretInformation[] outSecretInfo,
            string vaultName,
            out string errorMsg)
        {
            if (!EnumerateBlobs(
                filter,
                out EnumeratedBlob[] outBlobs,
                out errorMsg))
            {
                outSecretInfo = null;
                return false;
            }

            var outList = new List<SecretInformation>(outBlobs.Length);
            foreach (var item in outBlobs)
            {
                switch (item.TypeName)
                {
                    case ByteArrayType:
                        outList.Add(
                            new SecretInformation(
                                name: item.Name,
                                type: SecretType.ByteArray,
                                metadata: item.Metadata,
                                vaultName: vaultName));
                        break;

                    case StringType:
                        outList.Add(
                            new SecretInformation(
                                name: item.Name,
                                type: SecretType.String,
                                metadata: item.Metadata,
                                vaultName: vaultName));
                        break;

                    case SecureStringType:
                        outList.Add(
                            new SecretInformation(
                                name: item.Name,
                                type: SecretType.SecureString,
                                metadata: item.Metadata,
                                vaultName: vaultName));
                        break;

                    case PSCredentialType:
                        outList.Add(
                            new SecretInformation(
                                name: item.Name,
                                type: SecretType.PSCredential,
                                metadata: item.Metadata,
                                vaultName: vaultName));
                        break;

                    case HashtableType:
                        outList.Add(
                            new SecretInformation(
                                name: item.Name,
                                type: SecretType.Hashtable,
                                metadata: item.Metadata,
                                vaultName: vaultName));
                        break;
                }
            }

            outSecretInfo = outList.ToArray();
            errorMsg = string.Empty;
            return true;
        }

        #endregion

        #region Internal methods

        internal void UnlockLocalStore(
            SecureString password,
            int? passwordTimeout = null)
        {
            _secureStore.SetPassword(password);
            
            try
            {
                _secureStore.UpdateDataFromFile();
            }
            catch (PasswordRequiredException)
            {
                throw new PasswordRequiredException("Unable to unlock Microsoft.PowerShell.SecretStore vault. Password is invalid.");
            }

            if (passwordTimeout.HasValue)
            {
                _secureStore.SetPasswordTimer(passwordTimeout.Value);
            }
        }

        internal static void Reset()
        {
            lock (SyncObject)
            {
                LocalStore?.Dispose();
                LocalStore = null;
            }
        }

        internal void UpdatePassword(
            SecureString newPassword,
            SecureString oldPassword)
        {
            _secureStore.UpdatePassword(
                newPassword,
                oldPassword,
                skipPasswordRequiredCheck: false,
                skipConfigFileWrite: false);
        }

        internal bool UpdateConfiguration(
            SecureStoreConfig newConfigData,
            SecureString password,
            PSCmdlet cmdlet,
            out string errorMsg)
        {
            return _secureStore.UpdateConfigData(
                newConfigData,
                password,
                cmdlet,
                out errorMsg);
        }

        #endregion

        #region Private methods

        #region Helper methods

        private static string PrependHTTag(
            string hashName,
            string keyName)
        {
            return PSHashtableTag + hashName + keyName;
        }

        private static string RecoverKeyname(
            string str,
            string hashName)
        {
            return str.Substring((PSHashtableTag + hashName).Length);
        }

        internal static bool IsHTTagged(string str)
        {
            return str.StartsWith(PSHashtableTag);
        }

        private static SecureString PromptForPassword(
            string vaultName,
            PSCmdlet cmdlet)
        {
            if (SecureStoreFile.StoreFileExists())
            {
                // Prompt for existing local store file.
                var promptMessage = string.Format(CultureInfo.InvariantCulture,
                    VaultPaswordPrompt, vaultName);
                return Utils.PromptForPassword(
                    cmdlet: cmdlet,
                    verifyPassword: false,
                    message: promptMessage);
            }
            else
            {
                // Prompt for creation of new store file.
                var promptMessage = string.Format(CultureInfo.InvariantCulture,
                    NewVaultPasswordPrompt, vaultName);
                return Utils.PromptForPassword(
                    cmdlet: cmdlet,
                    verifyPassword: true,
                    message: promptMessage);
            }
        }

        #endregion

        #region Blob methods

        private bool ReadObjectImpl(
            string name,
            SecureString password,
            out object outObject,
            out string errorMsg)
        {
            if (!ReadBlob(
                name,
                password,
                out byte[] outBlob,
                out string typeName,
                out errorMsg))
            {
                outObject = null;
                return false;
            }

            errorMsg = string.Empty;
            switch (typeName)
            {
                case ByteArrayType:
                    outObject = outBlob;
                    return true;

                case StringType:
                    return ReadString(
                        outBlob,
                        out outObject);

                case SecureStringType:
                    return ReadSecureString(
                        outBlob,
                        out outObject);

                case PSCredentialType:
                    return ReadPSCredential(
                        outBlob,
                        out outObject);
                
                case HashtableType:
                    return ReadHashtable(
                        name,
                        outBlob,
                        password,
                        out outObject,
                        out errorMsg);

                default:
                    throw new InvalidOperationException("Invalid type. Types supported: byte[], string, SecureString, PSCredential, Hashtable");
            }
        }

        private bool WriteObjectImpl<T>(
            string name,
            T objectToWrite,
            Hashtable metadata,
            SecureString password,
            out string errorMsg)
        {
            switch (objectToWrite)
            {
                case byte[] blobToWrite:
                    return WriteBlob(
                        name,
                        blobToWrite,
                        ByteArrayType,
                        metadata,
                        password,
                        out errorMsg);

                case string stringToWrite:
                    return WriteString(
                        name,
                        stringToWrite,
                        metadata,
                        password,
                        out errorMsg);

                case SecureString secureStringToWrite:
                    return WriteSecureString(
                        name,
                        secureStringToWrite,
                        metadata,
                        password,
                        out errorMsg);

                case PSCredential credentialToWrite:
                    return WritePSCredential(
                        name,
                        credentialToWrite,
                        metadata,
                        password,
                        out errorMsg);

                case Hashtable hashtableToWrite:
                    return WriteHashtable(
                        name,
                        hashtableToWrite,
                        metadata,
                        password,
                        out errorMsg);
                
                default:
                    throw new InvalidOperationException("Invalid type. Types supported: byte[], string, SecureString, PSCredential, Hashtable");
            }
        }
        
        private bool WriteBlob(
            string name,
            byte[] blob,
            string typeName,
            Hashtable metadata,
            SecureString password,
            out string errorMsg)
        {
            // Supported additional data types are:
            //   string
            //   int
            //   DateTime
            var additionalData = new Dictionary<string, object>();
            if (metadata != null)
            {
                foreach (string key in metadata.Keys)
                {
                    var item = metadata[key];
                    if (item is PSObject psObjectItem)
                    {
                        item = psObjectItem.BaseObject;
                    }
                    if (!(item is string) && !(item is int) && !(item is DateTime))
                    {
                        errorMsg = "Microsoft.PowerShell.SecretStore accepts secret metadata only of types: string, int, DateTime";
                        return false;
                    }

                    additionalData.Add(key, item);
                }
            }

            return _secureStore.WriteBlob(
                name: name,
                blob: blob,
                typeName: typeName,
                attributes: DefaultTag,
                additionalData: additionalData,
                password: password,
                errorMsg: out errorMsg);
        }

        private bool ReadBlob(
            string name,
            SecureString password,
            out byte[] blob,
            out string typeName,
            out string errorMsg)
        {
            if (!_secureStore.ReadBlob(
                name: name,
                password: password,
                blob: out blob,
                metaData: out SecureStoreMetadata metadata,
                errorMsg: out errorMsg))
            {
                typeName = null;
                return false;
            }
            
            typeName = metadata.TypeName;
            return true;
        }

        private struct EnumeratedBlob
        {
            public string Name;
            public string TypeName;
            public ReadOnlyDictionary<string, object> Metadata;
        }

        private bool EnumerateBlobs(
            string filter,
            out EnumeratedBlob[] blobs,
            out string errorMsg)
        {
            if (!_secureStore.EnumerateBlobs(
                filter: filter,
                metaData: out SecureStoreMetadata[] metadata,
                out errorMsg))
            {
                blobs = null;
                return false;
            }

            List<EnumeratedBlob> blobArray = new List<EnumeratedBlob>(metadata.Length);
            foreach (var metaItem in metadata)
            {
                if (!IsHTTagged(metaItem.Name))
                {
                    blobArray.Add(
                        new EnumeratedBlob
                        {
                            Name = metaItem.Name,
                            TypeName = metaItem.TypeName,
                            Metadata = metaItem.AdditionalData
                        });
                }
            }

            blobs = blobArray.ToArray();
            return true;
        }

        private bool DeleteBlob(
            string name,
            SecureString password,
            out string errorMsg)
        {
            return _secureStore.DeleteBlob(
                name: name,
                password: password,
                errorMsg: out errorMsg);
        }

        #endregion

        #region String methods

        private bool WriteString(
            string name,
            string strToWrite,
            Hashtable metadata,
            SecureString password,
            out string errorMsg)
        {
            return WriteBlob(
                name: name,
                blob: Encoding.UTF8.GetBytes(strToWrite),
                typeName: StringType,
                metadata: metadata,
                password: password,
                errorMsg: out errorMsg);
        }

        private static bool ReadString(
            byte[] blob,
            out object outString)
        {
            outString = Encoding.UTF8.GetString(blob);
            return true;
        }

        #endregion

        #region String array methods

        //
        // String arrays are stored as a blob:
        //  <arrayCount>    - number of strings in array (sizeof(int32))
        //  <length1>       - length of first string     (sizeof(int32))
        //  <string1>       - first string bytes         (length1)
        //  <length2>       - length of second string    (sizeof(int32))
        //  <string2>       - second string bytes        (length2)
        //  ...
        //

        private bool WriteStringArray(
            string name,
            string[] strsToWrite,
            Hashtable metadata,
            SecureString password,
            out string errorMsg)
        {
            // Compute blob size
            int arrayCount = strsToWrite.Length;
            int blobLength = sizeof(Int32) * (arrayCount + 1);
            int[] aStrSizeBytes = new int[arrayCount];
            int iCount = 0;
            foreach (string str in strsToWrite)
            {
                var strSizeBytes = Encoding.UTF8.GetByteCount(str);
                aStrSizeBytes[iCount++] = strSizeBytes;
                blobLength += strSizeBytes;
            }

            byte[] blob = new byte[blobLength];
            var index = 0;

            // Array count
            byte[] data = BitConverter.GetBytes(arrayCount);
            foreach (var b in data)
            {
                blob[index++] = b;
            }

            // Array strings
            iCount = 0;
            foreach (var str in strsToWrite)
            {
                // String length
                data = BitConverter.GetBytes(aStrSizeBytes[iCount++]);
                foreach (var b in data)
                {
                    blob[index++] = b;
                }

                // String bytes
                data = Encoding.UTF8.GetBytes(str);
                foreach (var b in data)
                {
                    blob[index++] = b;
                }
            }

            Dbg.Assert(index == blobLength, "Blob size must be consistent");

            // Write blob
            return WriteBlob(
                name: name,
                blob: blob,
                typeName: HashtableType,
                metadata: metadata,
                password: password,
                errorMsg: out errorMsg);
        }

        private static void ReadStringArray(
            byte[] blob,
            out string[] outStrArray)
        {
            int index = 0;
            int arrayCount = BitConverter.ToInt32(blob, index);
            index += sizeof(Int32);

            outStrArray = new string[arrayCount];
            for (int iCount = 0; iCount < arrayCount; iCount++)
            {
                int strSizeBytes = BitConverter.ToInt32(blob, index);
                index += sizeof(Int32);

                outStrArray[iCount] = Encoding.UTF8.GetString(blob, index, strSizeBytes);
                index += strSizeBytes;
            }

            Dbg.Assert(index == blob.Length, "Blob length must be consistent");
        }

        #endregion
    
        #region SecureString methods

        private bool WriteSecureString(
            string name,
            SecureString strToWrite,
            Hashtable metadata,
            SecureString password,
            out string errorMsg)
        {
            if (Utils.GetDataFromSecureString(
                secureString: strToWrite,
                data: out byte[] data))
            {
                try
                {
                    return WriteBlob(
                        name: name,
                        blob: data,
                        typeName: SecureStringType,
                        metadata: metadata,
                        password: password,
                        errorMsg: out errorMsg);
                }
                finally
                {
                    CryptoUtils.ZeroOutData(data);
                }
            }
            
            errorMsg = "Unable to read SecureString data.";
            return false;
        }

        private static bool ReadSecureString(
            byte[] ssBlob,
            out object outSecureString)
        {
            try
            {
                if (Utils.GetSecureStringFromData(
                    data: ssBlob, 
                    outSecureString: out SecureString outString))
                {
                    outSecureString = outString;
                    return true;
                }
            }
            finally
            {
                CryptoUtils.ZeroOutData(ssBlob);
            }

            outSecureString = null;
            return false;
        }

        #endregion

        #region PSCredential methods

        //
        // PSCredential blob packing:
        //      <offset>    Contains offset to password data        Length: sizeof(int)
        //      <userName>  Contains UserName string bytes          Length: userData bytes
        //      <password>  Contains Password SecureString bytes    Length: ssData bytes
        //

        private bool WritePSCredential(
            string name,
            PSCredential credential,
            Hashtable metadata,
            SecureString password,
            out string errorMsg)
        {
            if (Utils.GetDataFromSecureString(
                secureString: credential.Password,
                data: out byte[] ssData))
            {
                byte[] blob = null;
                try
                {
                    // Get username string bytes
                    var userData = Encoding.UTF8.GetBytes(credential.UserName);

                    // Create offset bytes to SecureString data
                    var offset = userData.Length + sizeof(Int32);
                    var offsetData = BitConverter.GetBytes(offset);

                    // Create blob
                    blob = new byte[offset + ssData.Length];

                    // Copy all to blob
                    var index = 0;
                    foreach (var b in offsetData)
                    {
                        blob[index++] = b;
                    }
                    foreach (var b in userData)
                    {
                        blob[index++] = b;
                    }
                    foreach (var b in ssData)
                    {
                        blob[index++] = b;
                    }

                    // Write blob
                    return WriteBlob(
                        name: name,
                        blob: blob,
                        typeName: PSCredentialType,
                        metadata: metadata,
                        password: password,
                        errorMsg: out errorMsg);
                }
                finally
                {
                    CryptoUtils.ZeroOutData(ssData);
                    CryptoUtils.ZeroOutData(blob);
                }
            }
            
            errorMsg = "Unable to read SecureString data.";
            return false;
        }

        private static bool ReadPSCredential(
            byte[] blob,
            out object credential)
        {
            byte[] ssData = null;

            try
            {
                // UserName
                var offset = BitConverter.ToInt32(blob, 0);
                int index = sizeof(Int32);
                var userName = Encoding.UTF8.GetString(blob, index, (offset - index));

                // SecureString
                ssData = new byte[(blob.Length - offset)];
                index = 0;
                for (int i = offset; i < blob.Length; i++)
                {
                    ssData[index++] = blob[i];
                }

                if (Utils.GetSecureStringFromData(
                    ssData,
                    out SecureString secureString))
                {
                    credential = new PSCredential(userName, secureString);
                    return true;
                }
            }
            finally
            {
                CryptoUtils.ZeroOutData(blob);
                CryptoUtils.ZeroOutData(ssData);
            }

            credential = null;
            return false;
        }

        #endregion

        #region Hashtable methods

        //
        // Hash table values will be limited to the currently supported secret types:
        //  byte[]
        //  string
        //  SecureString
        //  PSCredential
        //
        // The values are stored as separate secrets with special name tags.
        //  <secretName1>
        //  <secretName2>
        //  <secretName3>
        //   ...
        //
    
        private bool WriteHashtable(
            string name,
            Hashtable hashtable,
            Hashtable metadata,
            SecureString password,
            out string errorMsg)
        {
            // Impose size limit
            if (hashtable.Count > MaxHashtableItemCount)
            {
                throw new ArgumentException(
                    string.Format(CultureInfo.InvariantCulture, 
                        "The provided Hashtable, {0}, has too many entries. The maximum number of entries is {1}.",
                        name, MaxHashtableItemCount));
            }

            // Create a list of hashtable entries.
            var entries = new Dictionary<string, object>();
            foreach (var key in hashtable.Keys)
            {
                var entry = hashtable[key];
                if (entry is PSObject psObjectEntry)
                {
                    entry = psObjectEntry.BaseObject;
                }
                var entryType = entry.GetType();
                if (entryType == typeof(byte[]) ||
                    entryType == typeof(string) ||
                    entryType == typeof(SecureString) ||
                    entryType == typeof(PSCredential))
                {
                    var entryName = PrependHTTag(name, key.ToString());
                    entries.Add(entryName, entry);
                }
                else
                {
                    throw new ArgumentException(
                        string.Format(CultureInfo.InstalledUICulture, 
                        "The object type for {0} Hashtable entry is not supported. Supported types are byte[], string, SecureString, PSCredential",
                        key));
                }
            }

            // Write the member name array.
            var hashTableEntryNames = new List<string>();
            foreach (var entry in entries)
            {
                hashTableEntryNames.Add(entry.Key);
            }
            if (!WriteStringArray(
                name: name,
                strsToWrite: hashTableEntryNames.ToArray(),
                metadata,
                password: password,
                errorMsg: out errorMsg))
            {
                return false;
            }

            // Write each entry as a separate secret.  Roll back on any failure.
            var success = false;
            try
            {
                foreach (var entry in entries)
                {
                    success = WriteObjectImpl(
                        name: entry.Key,
                        objectToWrite: entry.Value,
                        metadata: metadata,
                        password: password,
                        errorMsg: out errorMsg);
                    
                    if (!success)
                    {
                        break;
                    }
                }

                return success;
            }
            finally
            {
                if (!success)
                {
                    // Roll back.
                    // Remove any Hashtable secret that was written, ignore errors.
                    foreach (var entry in entries)
                    {
                        DeleteBlob(
                            name: entry.Key,
                            password: password,
                            errorMsg: out string _);
                    }

                    // Remove the Hashtable member names.
                    DeleteBlob(
                        name: name,
                        password: password,
                        errorMsg: out string _);
                }
            }
        }

        private bool ReadHashtable(
            string name,
            byte[] blob,
            SecureString password,
            out object outHashtable,
            out string errorMsg)
        {
            // Get array of Hashtable secret names.
            ReadStringArray(
                blob,
                out string[] entryNames);
            
            outHashtable = null;
            var hashtable = new Hashtable();
            foreach (var entryName in entryNames)
            {
                if (ReadObjectImpl(
                    entryName,
                    password,
                    out object outObject,
                    out errorMsg))
                {
                    hashtable.Add(
                    RecoverKeyname(entryName, name),
                    outObject);
                }
            }

            outHashtable = hashtable;
            errorMsg = string.Empty;
            return true;
        }

        private bool DeleteHashtable(
            string name,
            SecureString password,
            out string errorMsg)
        {
            // Get array of Hashtable secret names.
            if (!ReadBlob(
                name,
                password,
                out byte[] blob,
                out string typeName,
                out errorMsg))
            {
                return false;
            }

            ReadStringArray(
                blob,
                out string[] entryNames);

            // Delete each Hashtable entry secret.
            foreach (var entryName in entryNames)
            {
                DeleteBlob(
                    name: entryName,
                    password: password,
                    out errorMsg);
            }

            // Delete the Hashtable secret names list.
            DeleteBlob(
                name: name,
                password: password,
                out errorMsg);

            return true;
        }

        #endregion
    
        #endregion
    }

    #endregion
}
