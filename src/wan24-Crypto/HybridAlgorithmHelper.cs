using wan24.Core;

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
                if (value is not null && !value.CanExchangeKey) throw new ArgumentException("Algorithm can't key exchange", nameof(value));
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
                if (value is not null && !value.CanSign) throw new ArgumentException("Algorithm can't sign", nameof(value));
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
            try
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
                options ??= EncryptionHelper.GetDefaultOptions(options);
                // Key exchange algorithm
                if (keyExchangeAlgorithm is not null && options.AsymmetricAlgorithm is not null && options.AsymmetricCounterAlgorithm is null)
                    options.AsymmetricCounterAlgorithm = keyExchangeAlgorithm.Name;
                // KDF algorithm
                if (
                    kdfAlgorithm is not null &&
                    (options.KdfAlgorithm is not null || options.KdfAlgorithmIncluded || options.RequireKdf || options.RequireCounterKdf) &&
                    options.CounterKdfAlgorithm is null
                    )
                {
                    options.CounterKdfAlgorithm = kdfAlgorithm.Name;
                    options.CounterKdfIterations = kdfAlgorithm.DefaultIterations;
                    options.CounterKdfOptions = kdfAlgorithm.DefaultKdfOptions;
                }
                // MAC algorithm
                if (
                    macAlgorithm is not null &&
                    (
                        EncryptionHelper.GetAlgorithm(options.Algorithm ?? EncryptionHelper.DefaultAlgorithm.Name).RequireMacAuthentication ||
                        options.MacAlgorithm is not null || options.MacIncluded || options.MacAlgorithmIncluded || options.RequireCounterMac
                    ) &&
                    options.CounterMacAlgorithm is null
                    )
                    options.CounterMacAlgorithm = macAlgorithm.Name;
                return options;
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }

        /// <summary>
        /// Get hybrid key exchange options
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>Hybrid key exchange options</returns>
        public static CryptoOptions GetKeyExchangeOptions(CryptoOptions? options = null)
        {
            try
            {
                IAsymmetricAlgorithm? keyExchangeAlgorithm;
                lock (SyncObject) keyExchangeAlgorithm = _KeyExchangeAlgorithm;
                options ??= AsymmetricHelper.GetDefaultKeyExchangeOptions();
                // Key exchange algorithm
                if (keyExchangeAlgorithm is not null && options.AsymmetricCounterAlgorithm is null) options.AsymmetricCounterAlgorithm = keyExchangeAlgorithm.Name;
                return options;
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }

        /// <summary>
        /// Get hybrid signature options
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>Hybrid signature options</returns>
        public static CryptoOptions GetSignatureOptions(CryptoOptions? options = null)
        {
            try
            {
                IAsymmetricAlgorithm? signatureAlgorithm;
                lock (SyncObject) signatureAlgorithm = _SignatureAlgorithm;
                options ??= AsymmetricHelper.GetDefaultSignatureOptions();
                // Signature algorithm
                if (signatureAlgorithm is not null && options.AsymmetricCounterAlgorithm is null) options.AsymmetricCounterAlgorithm = signatureAlgorithm.Name;
                return options;
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }

        /// <summary>
        /// Get hybrid key exchange data (password will be set to <see cref="CryptoOptions.Password"/>)
        /// </summary>
        /// <param name="keyExchangeData">Key exchange data</param>
        /// <param name="options">Options</param>
        /// <returns>Key exchange data</returns>
        public static void GetKeyExchangeData(KeyExchangeDataContainer keyExchangeData, CryptoOptions options)
        {
            byte[]? pwd = null;
            CryptoOptions? kedOptions = null;
            try
            {
                if (options.CounterPrivateKey is not IKeyExchangePrivateKey key) throw new ArgumentException("Missing counter private key", nameof(options));
                if (options.Password is null) throw new ArgumentException("No password yet", nameof(options));
                kedOptions = new()
                {
                    PrivateKey = options.CounterPrivateKey,
                    PublicKey = options.CounterPublicKey
                };
                (pwd, keyExchangeData.CounterKeyExchangeData) = key.GetKeyExchangeData(options: kedOptions);
                options.Password = options.Password.ExtendKey(pwd);
                pwd = null;
            }
            catch (CryptographicException)
            {
                pwd?.Clear();
                throw;
            }
            catch (Exception ex)
            {
                pwd?.Clear();
                throw CryptographicException.From(ex);
            }
            finally
            {
                kedOptions?.Clear();
            }
        }

        /// <summary>
        /// Derive a hybrid key (will be set to <see cref="CryptoOptions.Password"/>)
        /// </summary>
        /// <param name="keyExchangeData">Key exchange data</param>
        /// <param name="options">Options</param>
        public static void DeriveKey(KeyExchangeDataContainer keyExchangeData, CryptoOptions options)
        {
            try
            {
                if (keyExchangeData.CounterKeyExchangeData is null) throw new ArgumentException("Missing counter key exchange data", nameof(keyExchangeData));
                if (options.PrivateKey is not IKeyExchangePrivateKey key) throw new ArgumentException("Missing valid private key", nameof(options));
                if (options.CounterPrivateKey is not IKeyExchangePrivateKey counterKey) throw new ArgumentException("Missing valid counter private key", nameof(options));
                byte[]? key1 = null,
                    key2 = null;
                try
                {
                    key1 = key.DeriveKey(keyExchangeData.KeyExchangeData);
                    key2 = counterKey.DeriveKey(keyExchangeData.CounterKeyExchangeData);
                    options.Password?.Clear();
                    options.Password = key1.ExtendKey(key2);
                }
                catch
                {
                    key1?.Clear();
                    key2?.Clear();
                    throw;
                }
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }

        /// <summary>
        /// Stretch a password hybrid (will be set to <see cref="CryptoOptions.Password"/>)
        /// </summary>
        /// <param name="options">Options</param>
        public static void StretchPassword(CryptoOptions options)
        {
            try
            {
                if (options.Password is null) throw new ArgumentException("No password", nameof(options));
                KdfAlgorithmBase algo = KdfHelper.GetAlgorithm(options.CounterKdfAlgorithm ?? _KdfAlgorithm?.Name ?? KdfHelper.DefaultAlgorithm.Name);
                CryptoOptions hybridOptions = algo.DefaultOptions;
                hybridOptions.KdfIterations = options.CounterKdfIterations;
                hybridOptions.KdfOptions = options.CounterKdfOptions;
                using SecureByteArrayRefStruct oldPwd = new(options.Password);
                (options.Password, options.CounterKdfSalt) = algo.Stretch(options.Password, options.Password.Length, options.CounterKdfSalt, hybridOptions);
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }

        /// <summary>
        /// Compute a hybrid MAC (will be set to <see cref="CryptoOptions.Mac"/>)
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>Hybrid MAC</returns>
        public static void ComputeMac(CryptoOptions options)
        {
            try
            {
                if (options.Mac is null) throw new ArgumentException("No MAC", nameof(options));
                if (options.Password is null && options.MacPassword is null) throw new ArgumentException("No password", nameof(options));
                CryptoOptions hybridOptions = MacHelper.GetAlgorithm(options.CounterMacAlgorithm ?? _MacAlgorithm?.Name ?? MacHelper.DefaultAlgorithm.Name).DefaultOptions;
                options.Mac = options.Mac.Mac(options.MacPassword ?? options.Password!, hybridOptions);
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw new CryptographicException(ex.Message, ex);
            }
        }

        /// <summary>
        /// Sign hybrid (will set the counter signature to <see cref="SignatureContainer.CounterSignature"/>)
        /// </summary>
        /// <param name="signature">Signature</param>
        /// <param name="options">Options</param>
        public static void Sign(SignatureContainer signature, CryptoOptions options)
        {
            try
            {
                if (options.CounterPrivateKey is not ISignaturePrivateKey key) throw new ArgumentException("Missing counter private key", nameof(options));
                signature.CounterSignature = key.SignHashRaw(signature.CreateSignatureHash(forCounterSignature: true));
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }

        /// <summary>
        /// Validate a counter signature
        /// </summary>
        /// <param name="signature">Signature</param>
        /// <returns>If the counter signature is valid</returns>
        public static bool ValidateCounterSignature(SignatureContainer signature)
        {
            try
            {
                if (signature.CounterSignature is null) throw new ArgumentException("No counter signature", nameof(signature));
                using ISignaturePublicKey counterSignerPublicKey = signature.CounterSignerPublicKey ?? throw new InvalidDataException("Missing counter signer public key");
                return counterSignerPublicKey.ValidateSignatureRaw(signature.CounterSignature, signature.CreateSignatureHash(forCounterSignature: true), throwOnError: false);
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }
    }
}
