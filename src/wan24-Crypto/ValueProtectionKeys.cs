using System.Diagnostics.CodeAnalysis;
using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Value protection keys
    /// </summary>
    public static class ValueProtectionKeys
    {
        /// <summary>
        /// Default TPM MAC algorithm name
        /// </summary>
        public const string DEFAULT_TPM_MAC_ALGORITHM = "TPMHMAC-SHA256";

        /// <summary>
        /// Keys
        /// </summary>
        private static readonly Dictionary<ValueProtectionLevels, ISecureValue> Keys = [];
        /// <summary>
        /// MAC algorithm name
        /// </summary>
        private static string _MacAlgorithm = MacHelper.DefaultAlgorithm.Name;
        /// <summary>
        /// TPM MAC algorithm name
        /// </summary>
        private static string _TpmMacAlgorithm;

        /// <summary>
        /// Constructor
        /// </summary>
        static ValueProtectionKeys()
        {
            _TpmMacAlgorithm = (from algo in MacHelper.Algorithms.Values
                                where algo.UsesTpm
                                orderby algo.MacLength descending
                                select algo.Name)
                                .FirstOrDefault() ?? DEFAULT_TPM_MAC_ALGORITHM;
        }

        /// <summary>
        /// TPM MAC algorithm name (will throw when setting to a non-registered (or non-TPM) algorithm; see <c>wan24-Crypto-TPM</c>)
        /// </summary>
        public static string TpmMacAlgorithmName
        {
            get => _TpmMacAlgorithm;
            set
            {
                MacAlgorithmBase algo = MacHelper.GetAlgorithm(value);
                if (!algo.UsesTpm) throw new ArgumentException($"{algo.DisplayName} (\"{algo.Name}\", #{algo.Value}) doesn't use a TPM");
                _TpmMacAlgorithm = value;
            }
        }

        /// <summary>
        /// MAC algorithm name (will throw when setting to a non-registered algorithm)
        /// </summary>
        public static string MacAlgorithmName
        {
            get => _MacAlgorithm;
            set
            {
                MacHelper.GetAlgorithm(value);
                _MacAlgorithm = value;
            }
        }

        /// <summary>
        /// Set a key
        /// </summary>
        /// <param name="level">Value protection level</param>
        /// <param name="protectionKey">Protection key (will be disposed!)</param>
        public static void Set(in ValueProtectionLevels level, in ISecureValue protectionKey)
        {
            Remove(level);
            using (SecureByteArrayRefStruct protectionKeyValue = new(protectionKey.Value))
                protectionKey.Value = ValueProtection.DefaultProtect(protectionKeyValue.Array, level.GetScope());
            Keys[level] = protectionKey;
        }

        /// <summary>
        /// Set a key
        /// </summary>
        /// <param name="level">Value protection level</param>
        /// <param name="protectionKey">Protection key (will be cleared!)</param>
        public static void Set2(in ValueProtectionLevels level, in byte[] protectionKey)
        {
            if (level == ValueProtectionLevels.None) throw new ArgumentException("No value protection level", nameof(level));
            Set(level, new SecureValue(protectionKey));
        }

        /// <summary>
        /// Determine if a key was defined for a value protection level
        /// </summary>
        /// <param name="level">Value protection level</param>
        /// <returns>Ifa key was defined</returns>
        public static bool Contains(in ValueProtectionLevels level)
        {
            if (level == ValueProtectionLevels.None) throw new ArgumentException("No value protection level", nameof(level));
            return Keys.ContainsKey(level);
        }

        /// <summary>
        /// Remove a key for a value protection level
        /// </summary>
        /// <param name="level">Value protection level</param>
        public static void Remove(in ValueProtectionLevels level)
        {
            if (level == ValueProtectionLevels.None) throw new ArgumentException("No value protection level", nameof(level));
            if (Keys.Remove(level, out ISecureValue? existingValue)) existingValue.Dispose();
        }

        /// <summary>
        /// Get a key
        /// </summary>
        /// <param name="level">Value protection level</param>
        /// <param name="key">Manual entered user password (won't be disposed)</param>
        /// <returns>Key (don't forget to dispose!)</returns>
        public static SecureByteArray Get(in ValueProtectionLevels level, in SecureByteArray? key = null)
        {
            if (level == ValueProtectionLevels.None) throw new ArgumentException("No value protection level", nameof(level));
            if (!Keys.TryGetValue(level, out ISecureValue? protectedKey)) throw new ArgumentException("Key not found", nameof(level));
            if (level.RequiresPasswordInput() != key is not null) throw new ArgumentException("User password (not) expectd", nameof(key));
            MacAlgorithmBase? tpmMac = level.RequiresTpm() ? MacHelper.GetAlgorithm(_TpmMacAlgorithm) : null,
                mac = key is null || tpmMac is not null ? null : MacHelper.GetAlgorithm(_MacAlgorithm);
            if (tpmMac is not null && !tpmMac.UsesTpm)
                throw new InvalidProgramException($"{nameof(ValueProtectionKeys)}.{nameof(TpmMacAlgorithmName)} algorithm \"{_TpmMacAlgorithm}\" doesn't use a TPM");
            using SecureByteArrayRefStruct protectedKeyValue = new(protectedKey.Value);
            if (tpmMac is null && key is null) return new(ValueProtection.DefaultUnprotect(protectedKeyValue.Array, level.GetScope()));
            using SecureByteArrayRefStruct unprotectedKeyValue = new(ValueProtection.DefaultUnprotect(protectedKeyValue.Array, level.GetScope()));
            return new(tpmMac is null ? mac!.Mac(unprotectedKeyValue.Span, key!.Array) : tpmMac.Mac(unprotectedKeyValue.Span, key?.Array ?? []));
        }

        /// <summary>
        /// Get a key
        /// </summary>
        /// <param name="level">Value protection level</param>
        /// <param name="key">Manual entered user password (won't be disposed)</param>
        /// <param name="result">Key (don't forget to dispose!)</param>
        /// <returns>If succeed</returns>
        public static bool TryGet(in ValueProtectionLevels level, in SecureByteArray? key, [NotNullWhen(returnValue: true)] out SecureByteArray? result)
        {
            try
            {
                if (level == ValueProtectionLevels.None)
                {
                    ErrorHandling.Handle(new(new ArgumentException("No value protection level", nameof(level)), Constants.CRYPTO_ERROR_SOURCE));
                    result = null;
                    return false;
                }
                if (!Keys.TryGetValue(level, out ISecureValue? protectedKey))
                {
                    result = null;
                    return false;
                }
                if (level.RequiresPasswordInput() != key is not null)
                {
                    Logging.WriteWarning($"Value protection level {level} requires a manual entered user password to be given");
                    result = null;
                    return false;
                }
                MacAlgorithmBase? tpmMac = null,
                    mac = null;
                if(level.RequiresTpm() && !MacHelper.Algorithms.TryGetValue(_TpmMacAlgorithm, out tpmMac))
                {
                    Logging.WriteWarning($"{nameof(ValueProtectionKeys)}.{nameof(TpmMacAlgorithmName)} algorithm \"{_TpmMacAlgorithm}\" not found");
                    result = null;
                    return false;
                }
                if(tpmMac is not null && !tpmMac.UsesTpm)
                {
                    ErrorHandling.Handle(new(new InvalidProgramException($"{nameof(ValueProtectionKeys)}.{nameof(TpmMacAlgorithmName)} algorithm \"{_TpmMacAlgorithm}\" doesn't use a TPM"), Constants.CRYPTO_ERROR_SOURCE));
                    result = null;
                    return false;
                }
                if (key is not null && tpmMac is null && !MacHelper.Algorithms.TryGetValue(_MacAlgorithm, out mac))
                {
                    Logging.WriteWarning($"{nameof(ValueProtectionKeys)}.{nameof(MacAlgorithmName)} algorithm \"{_MacAlgorithm}\" not found");
                    result = null;
                    return false;
                }
                using SecureByteArrayRefStruct protectedKeyValue = new(protectedKey.Value);
                if (tpmMac is null && key is null)
                {
                    result = new(ValueProtection.DefaultUnprotect(protectedKeyValue.Array, level.GetScope()));
                }
                else
                {
                    using SecureByteArrayRefStruct unprotectedKeyValue = new(ValueProtection.DefaultUnprotect(protectedKeyValue.Array, level.GetScope()));
                    result = new(tpmMac is null ? mac!.Mac(unprotectedKeyValue.Span, key!.Array) : tpmMac.Mac(unprotectedKeyValue.Span, key?.Array ?? []));
                }
                return true;
            }
            catch (Exception ex)
            {
                ErrorHandling.Handle(new($"Exception when trying to get protection level {level} key", ex, Constants.CRYPTO_ERROR_SOURCE));
                result = null;
                return false;
            }
        }
    }
}
