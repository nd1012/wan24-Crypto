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
            if (
                keyExchangeAlgorithm != null &&
                (options.AsymmetricAlgorithm != null || options.AsymmetricAlgorithmIncluded || options.AsymmetricCounterAlgorithmIncluded || options.RequireAsymmetricAlgorithm || options.RequireAsymmetricCounterAlgorithm) &&
                options.AsymmetricCounterAlgorithm == null
                )
                options.AsymmetricCounterAlgorithm = keyExchangeAlgorithm.Name;
            // KDF algorithm
            if (
                kdfAlgorithm != null &&
                (options.KdfAlgorithm != null || options.KdfAlgorithmIncluded || options.CounterKdfAlgorithmIncluded || options.RequireKdf || options.RequireCounterKdf) &&
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
                    options.MacAlgorithm != null || options.CounterMacAlgorithmIncluded || options.MacIncluded || options.MacAlgorithmIncluded || options.RequireMac || options.RequireCounterMac
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
        /// Get hybrid key exchange data
        /// </summary>
        /// <param name="keyExchangeData">Key exchange data</param>
        /// <param name="options">Options</param>
        /// <returns>Key exchange data</returns>
        public static byte[] GetKeyExchangeData(byte[] keyExchangeData, CryptoOptions options)
        {
            if (options.CounterPrivateKey == null) throw new ArgumentException("Missing counter private key", nameof(options));
            using MemoryStream ms = new();
            ms.WriteBytes(keyExchangeData)
                .WriteBytes(options.CounterPrivateKey.GetKeyExchangeData(options));
            return ms.ToArray();
        }

        /// <summary>
        /// Derive a hybrid key
        /// </summary>
        /// <param name="keyExchangeData">Key exchange data</param>
        /// <param name="options">Options</param>
        /// <returns>Hybrid key</returns>
        public static byte[] DeriveKey(byte[] keyExchangeData, CryptoOptions options)
        {
            if (options.PrivateKey == null) throw new ArgumentException("Missing private key", nameof(options));
            if (options.CounterPrivateKey == null) throw new ArgumentException("Missing counter private key", nameof(options));
            using MemoryStream ms = new(keyExchangeData);
            byte[]? kex1 = null,
                kex2 = null,
                key1 = null,
                key2 = null,
                res = null;
            try
            {
                kex1 = ms.ReadBytes(options.SerializerVersion, minLen: 1, maxLen: ushort.MaxValue).Value;
                kex2 = ms.ReadBytes(options.SerializerVersion, minLen: 1, maxLen: ushort.MaxValue).Value;
                key1 = options.PrivateKey.DeriveKey(kex1);
                key2 = options.CounterPrivateKey.DeriveKey(kex2);
                res = new byte[key1.Length + key2.Length];
                key1.AsSpan().CopyTo(res.AsSpan());
                key2.AsSpan().CopyTo(res.AsSpan()[key1.Length..]);
                return res;
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
                kex1?.Clear();
                kex2?.Clear();
                key1?.Clear();
                key2?.Clear();
            }
        }

        /// <summary>
        /// Stretch a password hybrid
        /// </summary>
        /// <param name="pwd">Stretched password</param>
        /// <param name="options">Options</param>
        /// <returns>Hybrid stretched key</returns>
        public static byte[] StretchPassword(byte[] pwd, CryptoOptions options)
        {
            EncryptionAlgorithmBase encryption = EncryptionHelper.GetAlgorithm(options.Algorithm ?? EncryptionHelper.DefaultAlgorithm.Name);
            KdfAlgorithmBase algo = KdfHelper.GetAlgorithm(options.CounterKdfAlgorithm ?? _KdfAlgorithm?.Name ?? KdfHelper.DefaultAlgorithm.Name);
            CryptoOptions hybridOptions = algo.DefaultOptions;
            hybridOptions.KdfIterations = options.CounterKdfIterations;
            (byte[] res, options.CounterKdfSalt) = algo.Stretch(pwd, encryption.KeySize, options.CounterKdfSalt, hybridOptions);
            return res;
        }

        /// <summary>
        /// Compute a hybrid MAC
        /// </summary>
        /// <param name="mac">Hybrid MAC</param>
        /// <param name="options">Options</param>
        /// <returns>Hybrid MAC</returns>
        public static byte[] ComputeMac(byte[] mac, CryptoOptions options)
        {
            if (options.Password == null) throw new ArgumentException("No password", nameof(options));
            CryptoOptions hybridOptions = MacHelper.GetAlgorithm(options.CounterMacAlgorithm ?? _MacAlgorithm?.Name ?? MacHelper.DefaultAlgorithm.Name).DefaultOptions;
            return mac.Mac(options.Password, hybridOptions);
        }

        /// <summary>
        /// Sign hybrid
        /// </summary>
        /// <param name="signature">Signature</param>
        /// <param name="options">Options</param>
        /// <returns>Hybrid signature (RFC 3279 DER sequence)</returns>
        public static byte[] Sign(SignatureContainer signature, CryptoOptions options)
        {
            if (options.CounterPrivateKey == null) throw new ArgumentException("Missing counter private key", nameof(options));
            return options.CounterPrivateKey.SignHashRaw(signature.CreateSignatureHash(forCounterSignature: true));
        }

        /// <summary>
        /// Validate a counter signature
        /// </summary>
        /// <param name="signature">Signature</param>
        /// <returns>If the counter signature is valid</returns>
        public static bool ValidateCounterSignature(SignatureContainer signature)
        {
            if (signature.CounterSignature == null) throw new ArgumentException("No counter signature", nameof(signature));
            using IAsymmetricPublicKey counterSignerPublicKey = signature.CounterSignerPublicKey ?? throw new InvalidDataException("Missing counter signer public key");
            return counterSignerPublicKey.ValidateSignatureRaw(signature.CounterSignature, signature.CreateSignatureHash(forCounterSignature: true), throwOnError: false);
        }
    }
}
