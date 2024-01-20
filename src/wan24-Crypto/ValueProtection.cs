using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Value protection helper
    /// </summary>
    public static class ValueProtection
    {
        /// <summary>
        /// Process scope key
        /// </summary>
        private static ISecureValue _ProcessScopeKey;
        /// <summary>
        /// System scope key
        /// </summary>
        private static ISecureValue _SystemScopeKey;
        /// <summary>
        /// User scope key
        /// </summary>
        private static ISecureValue _UserScopeKey;

        /// <summary>
        /// Constructor
        /// </summary>
        static ValueProtection()
        {
            _ProcessScopeKey = new SecureValue(RND.GetBytes(64));
            string system = $"{Environment.MachineName}[{typeof(ValueProtection).Assembly.Location}]";
            _UserScopeKey = new SecureValue(HashHelper.DefaultAlgorithm.Hash($"{Environment.UserDomainName}\\{Environment.UserName}@{system}".GetBytes()));
            _SystemScopeKey = new SecureValue(HashHelper.DefaultAlgorithm.Hash(system.GetBytes()));
        }

        /// <summary>
        /// Process scope key
        /// </summary>
        public static ISecureValue ProcessScopeKey
        {
            get => _ProcessScopeKey;
            set
            {
                using ISecureValue existing = _ProcessScopeKey;
                _ProcessScopeKey = value;
            }
        }

        /// <summary>
        /// User scope key
        /// </summary>
        public static ISecureValue UserScopeKey
        {
            get => _UserScopeKey;
            set
            {
                using ISecureValue existing = _UserScopeKey;
                _UserScopeKey = value;
            }
        }

        /// <summary>
        /// System scope key
        /// </summary>
        public static ISecureValue SystemScopeKey
        {
            get => _SystemScopeKey;
            set
            {
                using ISecureValue existing = _SystemScopeKey;
                _SystemScopeKey = value;
            }
        }

        /// <summary>
        /// Protect a value
        /// </summary>
        public static ProtectValue_Delegate Protect { get; set; } = DefaultProtect;

        /// <summary>
        /// Unprotect a value
        /// </summary>
        public static UnprotectValue_Delegate Unprotect { get; set; } = DefaultUnprotect;

        /// <summary>
        /// Get the key for a scope
        /// </summary>
        /// <param name="scope">Scope</param>
        /// <returns>Key (should be cleared!)</returns>
        public static byte[] GetScopeKey(Scope scope) => scope switch
        {
            Scope.Process => _ProcessScopeKey.Value,
            Scope.User => _UserScopeKey.Value,
            Scope.System => _SystemScopeKey.Value,
            _ => throw new ArgumentException("Invalid scope", nameof(scope))
        };

        /// <summary>
        /// Protect a value (default protect handler)
        /// </summary>
        /// <param name="value">Value to protect (won't be cleared)</param>
        /// <param name="scope">Scope</param>
        /// <returns>Protected value</returns>
        public static byte[] DefaultProtect(byte[] value, Scope scope = Scope.Process)
        {
            using SecureByteArrayRefStruct key = new(GetScopeKey(scope));
            return value.Encrypt(key);
        }

        /// <summary>
        /// Unprotect a value (default unprotect handler)
        /// </summary>
        /// <param name="protectedValue">Protected value (won't be cleared)</param>
        /// <param name="scope">Scope</param>
        /// <returns>Unprotected value</returns>
        public static byte[] DefaultUnprotect(byte[] protectedValue, Scope scope = Scope.Process)
        {
            using SecureByteArrayRefStruct key = new(GetScopeKey(scope));
            return protectedValue.Decrypt(key);
        }

        /// <summary>
        /// Delegate for a value protection handler
        /// </summary>
        /// <param name="value">Value to protect (won't be cleared)</param>
        /// <param name="scope">Scope</param>
        /// <returns>Protected value</returns>
        public delegate byte[] ProtectValue_Delegate(byte[] value, Scope scope = Scope.Process);
        /// <summary>
        /// Delegate for a value unprotection handler
        /// </summary>
        /// <param name="protectedValue">Protected value (won't be cleared)</param>
        /// <param name="scope">Scope</param>
        /// <returns>Unprotected value</returns>
        public delegate byte[] UnprotectValue_Delegate(byte[] protectedValue, Scope scope = Scope.Process);

        /// <summary>
        /// Scope
        /// </summary>
        public enum Scope
        {
            /// <summary>
            /// Current process
            /// </summary>
            [DisplayText("Current process context")]
            Process,
            /// <summary>
            /// Current user
            /// </summary>
            [DisplayText("Current user context")]
            User,
            /// <summary>
            /// System
            /// </summary>
            [DisplayText("Local system context")]
            System
        }
    }
}
