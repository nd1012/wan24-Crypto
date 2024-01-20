using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Value protection level enumeration
    /// </summary>
    public enum ValueProtectionLevels : byte
    {
        /// <summary>
        /// None
        /// </summary>
        [DisplayText("No value protection")]
        None = 0,
        /// <summary>
        /// TPM protected automatted local mashine key (generated; must be used with the TPM)
        /// </summary>
        [DisplayText("TPM protected automatted local mashine key")]
        AutoDeviceTpm = 1,
        /// <summary>
        /// Automatted online device key (requires an authentication key to be available offline)
        /// </summary>
        [DisplayText("Automatted online device key")]
        AutoOnlineDevice = 2,
        /// <summary>
        /// TPM protected automatted online device key (requires an authentication key to be available offline; must be used with the TPM)
        /// </summary>
        [DisplayText("TPM protected automatted online device key")]
        AutoOnlineDeviceTpm = 3,
        /// <summary>
        /// Automatted online user authentication (requires an authentication key to be available offline)
        /// </summary>
        [DisplayText("Automatted online user authentication")]
        AutoOnlineUser = 4,
        /// <summary>
        /// TPM protected automatted online user authentication (requires an authentication key to be available offline; must be used with the TPM)
        /// </summary>
        [DisplayText("TPM protected automatted online user authentication")]
        AutoOnlineUserTpm = 5,
        /// <summary>
        /// Manual user authentication with password (must be entered)
        /// </summary>
        [DisplayText("Manual user authentication with password")]
        UserPassword = 6,
        /// <summary>
        /// TPM protected manual user authentication with password (must be entered and used with the TPM)
        /// </summary>
        [DisplayText("TPM protected manual user authentication with password")]
        UserTpmPassword = 7,
        /// <summary>
        /// TPM protected manual online user authentication with password (requires an authentication key to be available offline; password must be entered and used with the TPM)
        /// </summary>
        [DisplayText("TPM protected manual user authentication with password")]
        OnlineUserTpmPassword = 8
    }
}
