using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto
{
    /// <summary>
    /// Hybrid algorithm helper
    /// </summary>
    public static class HybridAlgorithmHelper
    {
        /// <summary>
        /// Key exchange algorithm
        /// </summary>
        private static IAsymmetricAlgorithm? _KeyExchangeAlgorithm = null;
        /// <summary>
        /// Signature algorithm
        /// </summary>
        private static IAsymmetricAlgorithm? _SignatureAlgorithm = null;
        /// <summary>
        /// KDF algorithm
        /// </summary>
        private static KdfAlgorithmBase? _KdfAlgorithm = null;
        /// <summary>
        /// MAC algorithm
        /// </summary>
        private static MacAlgorithmBase? _MacAlgorithm = null;

        /// <summary>
        /// An object for thread synchronization
        /// </summary>
        public static object SyncObject { get; } = new();

        /// <summary>
        /// Key exchange algorithm
        /// </summary>
        public static IAsymmetricAlgorithm? KeyExchangeAlgorithm
        {
            get => _KeyExchangeAlgorithm;
            set
            {
                if (value != null && !value.CanExchangeKey) throw new ArgumentException("Algorithm can't key exchange", nameof(value));
                lock (SyncObject) _KeyExchangeAlgorithm = value;
            }
        }

        /// <summary>
        /// Signature algorithm
        /// </summary>
        public static IAsymmetricAlgorithm? SignatureAlgorithm
        {
            get => _SignatureAlgorithm;
            set
            {
                if (value != null && !value.CanSign) throw new ArgumentException("Algorithm can't sign", nameof(value));
                lock (SyncObject) _SignatureAlgorithm = value;
            }
        }

        /// <summary>
        /// KDF algorithm
        /// </summary>
        public static KdfAlgorithmBase? KdfAlgorithm
        {
            get => _KdfAlgorithm;
            set
            {
                lock (SyncObject) _KdfAlgorithm = value;
            }
        }

        /// <summary>
        /// MAC algorithm
        /// </summary>
        public static MacAlgorithmBase? MacAlgorithm
        {
            get => _MacAlgorithm;
            set
            {
                lock (SyncObject) _MacAlgorithm = value;
            }
        }

        /// <summary>
        /// Get hybrid encryption options
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>Hybrid encryption options</returns>
        public static CryptoOptions GetEncryptionOptions(CryptoOptions? options = null)
        {
            IAsymmetricAlgorithm? keyExchangeAlgorithm;
            KdfAlgorithmBase? kdfAlgorithm;
            MacAlgorithmBase? macAlgorithm;
            lock (SyncObject)
            {
                keyExchangeAlgorithm = _KeyExchangeAlgorithm;
                kdfAlgorithm = _KdfAlgorithm;
                macAlgorithm = _MacAlgorithm;
            }
            options = EncryptionHelper.GetDefaultOptions(options);
            // Key exchange algorithm
            if (keyExchangeAlgorithm != null && options.AsymmetricAlgorithm != null && options.AsymmetricCounterAlgorithm == null)
                options.AsymmetricCounterAlgorithm = keyExchangeAlgorithm.Name;
            // KDF algorithm
            if (
                kdfAlgorithm != null &&
                (options.KdfAlgorithm != null || options.KdfAlgorithmIncluded || options.RequireKdf || options.RequireCounterKdf) &&
                options.CounterKdfAlgorithm == null
                )
            {
                options.CounterKdfAlgorithm = kdfAlgorithm.Name;
                options.CounterKdfIterations = kdfAlgorithm.DefaultIterations;
            }
            // MAC algorithm
            if (
                macAlgorithm != null &&
                (
                    EncryptionHelper.GetAlgorithm(options.Algorithm ?? EncryptionHelper.DefaultAlgorithm.Name).RequireMacAuthentication ||
                    options.MacAlgorithm != null || options.MacIncluded || options.MacAlgorithmIncluded || options.RequireMac || options.RequireCounterMac
                ) &&
                options.CounterMacAlgorithm == null
                )
                options.CounterMacAlgorithm = macAlgorithm.Name;
            return options;
        }

        /// <summary>
        /// Get hybrid key exchange options
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>Hybrid key exchange options</returns>
        public static CryptoOptions GetKeyExchangeOptions(CryptoOptions? options = null)
        {
            IAsymmetricAlgorithm? keyExchangeAlgorithm;
            lock (SyncObject) keyExchangeAlgorithm = _KeyExchangeAlgorithm;
            options = AsymmetricHelper.GetDefaultKeyExchangeOptions(options);
            // Key exchange algorithm
            if (keyExchangeAlgorithm != null && options.AsymmetricCounterAlgorithm == null) options.AsymmetricCounterAlgorithm = keyExchangeAlgorithm.Name;
            return options;
        }

        /// <summary>
        /// Get hybrid signature options
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>Hybrid signature options</returns>
        public static CryptoOptions GetSignatureOptions(CryptoOptions? options = null)
        {
            IAsymmetricAlgorithm? signatureAlgorithm;
            lock (SyncObject) signatureAlgorithm = _SignatureAlgorithm;
            options = AsymmetricHelper.GetDefaultSignatureOptions(options);
            // Signature algorithm
            if (signatureAlgorithm != null && options.AsymmetricCounterAlgorithm == null) options.AsymmetricCounterAlgorithm = signatureAlgorithm.Name;
            return options;
        }

        /// <summary>
        /// Get hybrid key exchange data (password will be set to <see cref="CryptoOptions.Password"/>)
        /// </summary>
        /// <param name="keyExchangeData">Key exchange data</param>
        /// <param name="options">Options</param>
        public static void GetKeyExchangeData(KeyExchangeDataContainer keyExchangeData, CryptoOptions options)
        {
            if (options.CounterPrivateKey is not IKeyExchangePrivateKey key) throw new ArgumentException("Missing counter private key", nameof(options));
            if (options.Password == null) throw new ArgumentException("No password yet", nameof(options));
            (options.Password, keyExchangeData.CounterKeyExchangeData) = key.GetKeyExchangeData(options: options);
        }

        /// <summary>
        /// Derive a hybrid key (will be set to <see cref="CryptoOptions.Password"/>)
        /// </summary>
        /// <param name="keyExchangeData">Key exchange data</param>
        /// <param name="options">Options</param>
        public static void DeriveKey(KeyExchangeDataContainer keyExchangeData, CryptoOptions options)
        {
            if (keyExchangeData.CounterKeyExchangeData == null) throw new ArgumentException("Missing counter key exchange data", nameof(keyExchangeData));
            if (options.PrivateKey is not IKeyExchangePrivateKey key) throw new ArgumentException("Missing valid private key", nameof(options));
            if (options.CounterPrivateKey is not IKeyExchangePrivateKey counterKey) throw new ArgumentException("Missing valid counter private key", nameof(options));
            byte[]? key1 = null,
                key2 = null,
                res = null;
            try
            {
                key1 = key.DeriveKey(keyExchangeData.KeyExchangeData);
                key2 = counterKey.DeriveKey(keyExchangeData.CounterKeyExchangeData);
                res = new byte[key1.Length + key2.Length];
                key1.AsSpan().CopyTo(res.AsSpan());
                key2.AsSpan().CopyTo(res.AsSpan()[key1.Length..]);
                options.Password = res;
            }
            catch(CryptographicException)
            {
                res?.Clear();
                throw;
            }
            catch(Exception ex)
            {
                res?.Clear();
                throw new CryptographicException(ex.Message, ex);
            }
            finally
            {
                key1?.Clear();
                key2?.Clear();
            }
        }

        /// <summary>
        /// Stretch a password hybrid (will be set to <see cref="CryptoOptions.Password"/>)
        /// </summary>
        /// <param name="options">Options</param>
        public static void StretchPassword(CryptoOptions options)
        {
            if (options.Password == null) throw new ArgumentException("No password", nameof(options));
            byte[] pwd = options.Password;
            try
            {
                EncryptionAlgorithmBase encryption = EncryptionHelper.GetAlgorithm(options.Algorithm ?? EncryptionHelper.DefaultAlgorithm.Name);
                KdfAlgorithmBase algo = KdfHelper.GetAlgorithm(options.CounterKdfAlgorithm ?? _KdfAlgorithm?.Name ?? KdfHelper.DefaultAlgorithm.Name);
                CryptoOptions hybridOptions = algo.DefaultOptions;
                hybridOptions.KdfIterations = options.CounterKdfIterations;
                (options.Password, options.CounterKdfSalt) = algo.Stretch(options.Password, encryption.KeySize, options.CounterKdfSalt, hybridOptions);
            }
            finally
            {
                pwd.Clear();
            }
        }

        /// <summary>
        /// Compute a hybrid MAC (will be set to <see cref="CryptoOptions.Mac"/>)
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>Hybrid MAC</returns>
        public static void ComputeMac(CryptoOptions options)
        {
            if (options.Password == null) throw new ArgumentException("No password", nameof(options));
            if (options.Mac == null) throw new ArgumentException("No MAC", nameof(options));
            CryptoOptions hybridOptions = MacHelper.GetAlgorithm(options.CounterMacAlgorithm ?? _MacAlgorithm?.Name ?? MacHelper.DefaultAlgorithm.Name).DefaultOptions;
            options.Mac = options.Mac.Mac(options.Password, hybridOptions);
        }

        /// <summary>
        /// Sign hybrid
        /// </summary>
        /// <param name="signature">Signature</param>
        /// <param name="options">Options</param>
        public static void Sign(SignatureContainer signature, CryptoOptions options)
        {
            if (options.CounterPrivateKey is not ISignaturePrivateKey) throw new ArgumentException("Missing counter private key", nameof(options));
            signature.CounterSignature = ((ISignaturePrivateKey)options.CounterPrivateKey).SignHashRaw(signature.CreateSignatureHash(forCounterSignature: true));
        }

        /// <summary>
        /// Validate a counter signature
        /// </summary>
        /// <param name="signature">Signature</param>
        /// <returns>If the counter signature is valid</returns>
        public static bool ValidateCounterSignature(SignatureContainer signature)
        {
            if (signature.CounterSignature == null) throw new ArgumentException("No counter signature", nameof(signature));
            using ISignaturePublicKey counterSignerPublicKey = signature.CounterSignerPublicKey as ISignaturePublicKey ?? throw new InvalidDataException("Missing counter signer public key");
            return counterSignerPublicKey.ValidateSignatureRaw(signature.CounterSignature, signature.CreateSignatureHash(forCounterSignature: true), throwOnError: false);
        }
    }
}
