// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Management.Automation;
using System.Security;

namespace Microsoft.PowerShell.SecretStore
{
    #region Unlock-SecretStore

    /// <summary>
    /// Sets the local store password for the current session.
    /// Password will remain in effect for the session until the timeout expires.
    /// The password timeout is set in the local store configuration.
    /// </summary>
    [Cmdlet(VerbsCommon.Unlock, "SecretStore",
        DefaultParameterSetName = SecureStringParameterSet)]
    public sealed class UnlockSecretStoreCommand : PSCmdlet
    {
        #region Members

        private const string StringParameterSet = "StringParameterSet";
        private const string SecureStringParameterSet = "SecureStringParameterSet";

        #endregion

        #region Parameters

        /// <summary>
        /// Gets or sets a plain text password.
        /// </summary>
        [Parameter(ParameterSetName=StringParameterSet)]
        [ValidateNotNullOrEmpty]
        public string Password { get; set; }

        /// <summary>
        /// Gets or sets a SecureString password.
        /// </summary>
        [Parameter(Mandatory=true, ValueFromPipeline=true, ValueFromPipelineByPropertyName=true, ParameterSetName=SecureStringParameterSet)]
        public SecureString SecureStringPassword { get; set; }

        /// <summary>
        /// Gets or sets a password timeout value in seconds.
        /// </summary>
        [Parameter]
        [ValidateRange(-1, (Int32.MaxValue / 1000))]
        public int PasswordTimeout { get; set; }

        #endregion

        #region Overrides

        protected override void EndProcessing()
        {
            var passwordToSet = (ParameterSetName == StringParameterSet) ? Utils.ConvertToSecureString(Password) : SecureStringPassword;
            LocalSecretStore.GetInstance(
                password: passwordToSet).UnlockLocalStore(
                    password: passwordToSet,
                    passwordTimeout: MyInvocation.BoundParameters.ContainsKey(nameof(PasswordTimeout)) ? 
                        (int?)PasswordTimeout : null);
        }

        #endregion
    }

    #endregion

    #region Set-SecretStorePassword

    /// <summary>
    /// Updates the local store password to the new password provided.
    /// </summary>
    [Cmdlet(VerbsCommon.Set, "SecretStorePassword")]
    public sealed class SetSecretStorePasswordCommand : PSCmdlet
    {
        #region Overrides

        protected override void EndProcessing()
        {
            SecureString newPassword;
            SecureString oldPassword;
            oldPassword = Utils.PromptForPassword(
                cmdlet: this,
                verifyPassword: false,
                message: "Old password");
            newPassword = Utils.PromptForPassword(
                cmdlet: this,
                verifyPassword: true,
                message: "New password");

            LocalSecretStore.GetInstance(password: oldPassword).UpdatePassword(
                newPassword,
                oldPassword);
        }

        #endregion
    }

    #endregion

    #region Get-SecretStoreConfiguration

    [Cmdlet(VerbsCommon.Get, "SecretStoreConfiguration")]
    [OutputType(typeof(SecureStoreConfig))]
    public sealed class GetSecretStoreConfiguration : PSCmdlet
    {
        #region Overrides

        protected override void EndProcessing()
        {
            WriteObject(
                LocalSecretStore.GetInstance(cmdlet: this).Configuration);
        }

        #endregion
    }

    #endregion

    #region Set-SecretStoreConfiguration

    [Cmdlet(VerbsCommon.Set, "SecretStoreConfiguration", DefaultParameterSetName = ParameterSet,
        SupportsShouldProcess = true, ConfirmImpact = ConfirmImpact.High)]
    [OutputType(typeof(SecureStoreConfig))]
    public sealed class SetSecretStoreConfiguration : PSCmdlet
    {
        #region Members

        private const string ParameterSet = "ParameterSet";
        private const string DefaultParameterSet = "DefaultParameterSet";

        #endregion

        #region Parameters

        [Parameter(ParameterSetName = ParameterSet)]
        public SecureStoreScope Scope { get; set; }

        [Parameter(ParameterSetName = ParameterSet)]
        public Authenticate Authentication { get; set; }

        [Parameter(ParameterSetName = ParameterSet)]
        [ValidateRange(-1, (Int32.MaxValue / 1000))]
        public int PasswordTimeout { get; set; }

        [Parameter(ParameterSetName = ParameterSet)]
        public Interaction UserInteraction { get; set; }

        [Parameter(ParameterSetName = DefaultParameterSet)]
        public SwitchParameter Default { get; set; }

        [Parameter]
        public SwitchParameter Force { get; set; }

        #endregion

        #region Overrides

        protected override void BeginProcessing()
        {
            if (MyInvocation.BoundParameters.Count == 0)
            {
                ThrowTerminatingError(
                    new ErrorRecord(
                        exception: new PSInvalidOperationException("No parameter arguments were specified. Terminating operation."),
                        errorId: "SecretSToreSetConfigurationNoParameterArguments",
                        errorCategory: ErrorCategory.InvalidOperation,
                        this));
            }
        }

        protected override void EndProcessing()
        {
            if (Scope == SecureStoreScope.AllUsers)
            {
                ThrowTerminatingError(
                    new ErrorRecord(
                        exception: new PSNotSupportedException("AllUsers scope is not yet supported."),
                        errorId: "SecretStoreConfigurationNotSupported",
                        errorCategory: ErrorCategory.NotEnabled,
                        this));
            }

            if (!Force && !ShouldProcess(
                target: "SecretStore module local store",
                action: "Changes local store configuration"))
            {
                return;
            }

            var oldConfigData = LocalSecretStore.GetInstance(cmdlet: this).Configuration;
            SecureStoreConfig newConfigData;
            if (ParameterSetName == ParameterSet)
            {
                newConfigData = new SecureStoreConfig(
                    scope: MyInvocation.BoundParameters.ContainsKey(nameof(Scope)) ? Scope : oldConfigData.Scope,
                    authentication: MyInvocation.BoundParameters.ContainsKey(nameof(Authentication)) ? Authentication : oldConfigData.Authentication,
                    passwordTimeout: MyInvocation.BoundParameters.ContainsKey(nameof(PasswordTimeout)) ? PasswordTimeout : oldConfigData.PasswordTimeout,
                    userInteraction: MyInvocation.BoundParameters.ContainsKey(nameof(UserInteraction)) ? UserInteraction : oldConfigData.UserInteraction);
            }
            else
            {
                newConfigData = SecureStoreConfig.GetDefault();
            }

            if (!LocalSecretStore.GetInstance(cmdlet: this).UpdateConfiguration(
                newConfigData: newConfigData,
                cmdlet: this,
                out string errorMsg))
            {
                ThrowTerminatingError(
                    new ErrorRecord(
                        exception: new PSInvalidOperationException(errorMsg),
                        errorId: "SecretStoreConfigurationUpdateFailed",
                        errorCategory: ErrorCategory.InvalidOperation,
                        this));
            }

            WriteObject(newConfigData);
        }

        #endregion
    }

    #endregion

    #region Reset-SecretStore

    [Cmdlet(VerbsCommon.Reset, "SecretStore", 
        SupportsShouldProcess = true, ConfirmImpact = ConfirmImpact.High)]
    [OutputType(typeof(SecureStoreConfig))]
    public sealed class ResetSecretStoreCommand : PSCmdlet
    {
        #region Parmeters

        [Parameter]
        public SecureStoreScope Scope { get; set; }

        [Parameter]
        public Authenticate Authentication { get; set; }

        [Parameter]
        [ValidateRange(-1, (Int32.MaxValue / 1000))]
        public int PasswordTimeout { get; set; }

        [Parameter]
        public Interaction UserInteraction { get; set; }

        [Parameter]
        public SwitchParameter Force { get; set; }

        #endregion

        #region Overrides

        protected override void BeginProcessing()
        {
            if (Scope == SecureStoreScope.AllUsers)
            {
                ThrowTerminatingError(
                    new ErrorRecord(
                        exception: new PSNotSupportedException("AllUsers scope is not yet supported."),
                        errorId: "SecretStoreConfigurationNotSupported",
                        errorCategory: ErrorCategory.NotEnabled,
                        this));
            }

            WriteWarning("!!This operation will completely remove all SecretStore module secrets and reset configuration settings to default values!!");
        }

        protected override void EndProcessing()
        {
            bool yesToAll = false;
            bool noToAll = false;
            if (!Force && !ShouldContinue(
                query: "Are you sure you want to erase all secrets in SecretStore and reset configuration settings to default?",
                caption: "Reset SecretStore",
                hasSecurityImpact: true,
                ref yesToAll,
                ref noToAll))
            {
                return;
            }

            var defaultConfigData = SecureStoreConfig.GetDefault();
            var newConfigData = new SecureStoreConfig(
                scope: MyInvocation.BoundParameters.ContainsKey(nameof(Scope)) ? Scope : defaultConfigData.Scope,
                authentication: MyInvocation.BoundParameters.ContainsKey(nameof(Authentication)) ? Authentication : defaultConfigData.Authentication,
                passwordTimeout: MyInvocation.BoundParameters.ContainsKey(nameof(PasswordTimeout)) ? PasswordTimeout : defaultConfigData.PasswordTimeout,
                userInteraction: MyInvocation.BoundParameters.ContainsKey(nameof(UserInteraction)) ? UserInteraction : defaultConfigData.UserInteraction);

            if (!SecureStoreFile.RemoveStoreFile(out string errorMsg))
            {
                ThrowTerminatingError(
                    new ErrorRecord(
                        exception: new PSInvalidOperationException(errorMsg),
                        errorId: "ResetSecretStoreCannotRemoveStoreFile",
                        errorCategory: ErrorCategory.InvalidOperation,
                        targetObject: this));
            }

            if (!SecureStoreFile.WriteConfigFile(
                configData: newConfigData,
                out errorMsg))
            {
                ThrowTerminatingError(
                    new ErrorRecord(
                        exception: new PSInvalidOperationException(errorMsg),
                        errorId: "ResetSecretStoreCannotWriteConfigFile",
                        errorCategory: ErrorCategory.InvalidOperation,
                        targetObject: this));
            }

            LocalSecretStore.Reset();

            WriteObject(newConfigData);
        }

        #endregion
    }

    #endregion
}
