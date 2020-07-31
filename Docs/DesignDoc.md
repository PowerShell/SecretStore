# Microsoft.PowerShell.SecretStore Module Design

## Description

The Microsoft.PowerShell.SecretStore is a PowerShell module extension vault for Microsoft.PowerShell.SecretManagement.
It is a secure storage solution that stores secret data on a local machine.
It is based on .NET crypto APIs, and works on all PowerShell supported platforms for Windows, Linux, macOS.  

Secret data is stored at rest in encrypted form on the file system.
Secret data remains encrypted in memory, and is decrypted only when returned to a user query.  

The store file data integrity is verified using a cryptographic hash embedded in the file.  

The store can be configured to require a password or operate password-less.
Requiring a password is more secure since password-less operation relies solely on file system protections.
Password-less operation still encrypts data, but the encryption key is stored on file and is accessible.  

Configuration and data files are stored in user context locations, and have file permissions or access control lists limiting access to user only.  
Configuration options include password requirement, password timeout, and the ability to prompt user for password in interactive sessions.  
There is an unimplemented configuration option to allow `AllUser` access to the store, instead of `CurrentUser` only access.
This configuration not supported in the current implementation.  

## Files

Configuration and data are stored in separate files.
File location depends on the platform OS.  

For Windows platforms the location is:  
`%USERPROFILE%\AppData\Local\Microsoft\PowerShell\secretmanagement\localstore\`  

For Non-Windows platforms the location is:  
`~/.secretmanagement/localstore/`

### Scope

SecretStore was intended to be configurable and work in both user and machine wide scopes.
However, the current implementation supports only `CurrentUser` scope.  

### File permissions

On Windows platforms, file permissions are determined by an access control list on the containing directory, which restricts all access of the contents to the owning user.  

For Non-Windows platforms, file permissions are set to the owning user only.  

### Configuration file

The configuration data is stored on file in a simple json format.  

```json
{
  "StoreScope": "CurrentUser",
  "PasswordRequired": true,
  "PasswordTimeout": 900,
  "DoNotPrompt": false
}
```

The configuration file is encrypted with the current user name to prevent casual access or modification of the content.  

### Data file

The data file structure consists of five main sections:  

- File data hash

- Encryption key blob    (AES Encryption key)

- Encryption iv blob     (AES initialization vector)

- Secret metadata json   (Information about each secret item)

- Secret data blob       (Individual secret values)

The file data hash is a cryptographic hash of the key, iv, metadata, data, and is used verify file content integrity.  

The metadata is a json structure that contains information about each secret.  

```json
{
    "MetaData": [
    {
        "Name": "TestSecret1",
        "Type": "String",
        "Offset": 34593,
        "Size": 3500,
        "Attributes": {}
    },
    {
        "Name": "TestSecret2",
        "Type": "PSCredential",
        "Offset": 59837,
        "Size": 4200,
        "Attributes": {
            "UserName": "UserA"
        },
    }
    ]
}
```

The data blob is a byte array containing all secret values.
The metadata offset and size fields are used to extract the specific secret value blob.
Each secret value blob is individually encrypted.  

Both metadata and data blob secrets are encrypted with the encryption key, or the encryption key plus password, if password configuration is enabled.  

## Encryption

All encryption is performed using the .NET Core crypto APIs to ensure cross platform operation.
Both the configuration file and data files are encrypted.  

The configuration file encryption is different than the data file.
Configuration information determines whether a password is required and that must be known password based decryption can be performed.
So the configuration file is encrypted with the current user name.
This is not intended to be strong protection, but instead is a defense-in-depth measure to prevent casual access and modification of configuration data.  



## Data integrity

## Configuration



