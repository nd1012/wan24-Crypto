using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// <see cref="ValueProtectionLevels"/> extension methods
    /// </summary>
    public static class ValueProtectionLevelsExtensions
    {
        /// <summary>
        /// Does the value protection level require a manual user password input?
        /// </summary>
        /// <param name="level">Level</param>
        /// <returns>Manual user password input required?</returns>
        public static bool RequiresPasswordInput(this ValueProtectionLevels level) => level switch
        {
            ValueProtectionLevels.UserPassword => true,
            ValueProtectionLevels.UserTpmPassword => true,
            ValueProtectionLevels.OnlineUserTpmPassword => true,
            _  => false
        };

        /// <summary>
        /// Does the value protection level require a TPM?
        /// </summary>
        /// <param name="level">Level</param>
        /// <returns>TPM required?</returns>
        public static bool RequiresTpm(this ValueProtectionLevels level) => level switch
        {
            ValueProtectionLevels.AutoDeviceTpm => true,
            ValueProtectionLevels.AutoOnlineDeviceTpm => true,
            ValueProtectionLevels.AutoOnlineUserTpm => true,
            ValueProtectionLevels.UserTpmPassword => true,
            ValueProtectionLevels.OnlineUserTpmPassword => true,
            _ => false
        };

        /// <summary>
        /// Does the value protection level require a network (Internet) connection?
        /// </summary>
        /// <param name="level">Level</param>
        /// <returns>Network (Internet) required?</returns>
        public static bool RequiresNetwork(this ValueProtectionLevels level) => level switch
        {
            ValueProtectionLevels.AutoOnlineDevice => true,
            ValueProtectionLevels.AutoOnlineDeviceTpm => true,
            ValueProtectionLevels.AutoOnlineUser => true,
            ValueProtectionLevels.AutoOnlineUserTpm => true,
            ValueProtectionLevels.OnlineUserTpmPassword => true,
            _ => false
        };

        /// <summary>
        /// Get the value protection scope
        /// </summary>
        /// <param name="level">Level</param>
        /// <returns>Scope</returns>
        public static ValueProtection.Scope GetScope(this ValueProtectionLevels level) => level switch
        {
            ValueProtectionLevels.None => throw new ArgumentException("No value protection level", nameof(level)),
            ValueProtectionLevels.AutoDeviceTpm => ValueProtection.Scope.System,
            ValueProtectionLevels.AutoOnlineDevice => ValueProtection.Scope.System,
            ValueProtectionLevels.AutoOnlineDeviceTpm => ValueProtection.Scope.System,
            _ => ValueProtection.Scope.User
        };

        /// <summary>
        /// Protect a value
        /// </summary>
        /// <param name="level">Level</param>
        /// <param name="value">Value to protect (won't be cleared)</param>
        /// <param name="key">Manual entered user password (won't be disposed)</param>
        /// <returns>Protected value</returns>
        public static byte[] Protect(this ValueProtectionLevels level, in byte[] value, in SecureByteArray? key = null)
        {
            if (level == ValueProtectionLevels.None) throw new ArgumentException("No value protection level", nameof(level));
            using SecureByteArray valueKey = ValueProtectionKeys.Get(level, key);
            return value.Encrypt(valueKey.Array);
        }

        /// <summary>
        /// Unprotect a value
        /// </summary>
        /// <param name="level">Level</param>
        /// <param name="value">Protected value (won't be cleared)</param>
        /// <param name="key">Manual entered user password (won't be disposed)</param>
        /// <returns>Unprotected value</returns>
        public static byte[] Unprotect(this ValueProtectionLevels level, in byte[] value, in SecureByteArray? key = null)
        {
            if (level == ValueProtectionLevels.None) throw new ArgumentException("No value protection level", nameof(level));
            using SecureByteArray valueKey = ValueProtectionKeys.Get(level, key);
            return value.Decrypt(valueKey.Array);
        }
    }
}
