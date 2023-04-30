using wan24.Compression;

namespace wan24.Crypto
{
    /// <summary>
    /// <see cref="CryptoOptions"/> fluent extensions
    /// </summary>
    public static class CryptoOptionsFluentExtensions
    {
        /// <summary>
        /// Set encryption algorithm options
        /// </summary>
        /// <param name="options">Options</param>
        /// <param name="algo">Algorithm name</param>
        /// <returns>Options</returns>
        public static CryptoOptions WithEncryptionAlgorithm(this CryptoOptions options, string? algo = null)
        {
            algo ??= EncryptionHelper.DefaultAlgorithm.Name;
            EncryptionHelper.GetAlgorithm(algo);
            options.Algorithm = algo;
            return options;
        }

        /// <summary>
        /// Set encryption algorithm options
        /// </summary>
        /// <param name="options">Options</param>
        /// <param name="algo">Algorithm value</param>
        /// <returns>Options</returns>
        public static CryptoOptions WithEncryptionAlgorithm(this CryptoOptions options, int algo)
            => WithEncryptionAlgorithm(options, EncryptionHelper.GetAlgorithm(algo).Name);

        /// <summary>
        /// Remove encryption algorithm options
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>Options</returns>
        public static CryptoOptions WithoutEncryptionAlgorithm(this CryptoOptions options)
        {
            options.Algorithm = null;
            return options;
        }

        /// <summary>
        /// Add time critical options
        /// </summary>
        /// <param name="options">Options</param>
        /// <param name="maxAge">Maximum cipher age</param>
        /// <param name="maxTimeOffset">Maximum time offset</param>
        /// <returns></returns>
        public static CryptoOptions WithTimeCritics(this CryptoOptions options, TimeSpan maxAge, TimeSpan? maxTimeOffset = null)
        {
            options.MaximumAge = maxAge;
            if (maxTimeOffset != null) options.MaximumTimeOffset = maxTimeOffset;
            options.TimeIncluded = true;
            options.RequireTime = true;
            return options;
        }

        /// <summary>
        /// Disable time critical options
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>Options</returns>
        public static CryptoOptions WithoutTimeCritics(this CryptoOptions options)
        {
            options.MaximumAge = null;
            options.MaximumTimeOffset = null;
            options.TimeIncluded = false;
            options.RequireTime = false;
            return options;
        }

        /// <summary>
        /// Enable compression
        /// </summary>
        /// <param name="options">Options</param>
        /// <param name="compressionOptions">Compression options</param>
        /// <returns></returns>
        public static CryptoOptions WithCompression(this CryptoOptions options, CompressionOptions? compressionOptions = null)
        {
            options.Compressed = true;
            if (compressionOptions != null) options.Compression = compressionOptions;
            return options;
        }

        /// <summary>
        /// Disable compression
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>Options</returns>
        public static CryptoOptions WithoutCompression(this CryptoOptions options)
        {
            options.Compressed = false;
            options.Compression = null;
            return options;
        }

        /// <summary>
        /// Enable creating a MAC
        /// </summary>
        /// <param name="options">Options</param>
        /// <param name="algo">Algorithm name</param>
        /// <param name="included">Included in the header?</param>
        /// <param name="forceCoverWhole">Force the MAC to cover the whole data?</param>
        /// <returns>Options</returns>
        public static CryptoOptions WithMac(this CryptoOptions options, string? algo = null, bool included = true, bool forceCoverWhole = false)
        {
            algo ??= MacHelper.DefaultAlgorithm.Name;
            MacHelper.GetAlgorithm(algo);
            options.MacAlgorithm = algo;
            options.MacIncluded = true;
            options.MacAlgorithmIncluded = included;
            options.ForceMacCoverWhole = forceCoverWhole;
            options.RequireMac = true;
            options.RequireMacCoverWhole = forceCoverWhole;
            if (EncryptionHelper.UseHybridOptions && options.CounterMacAlgorithm == null)
            {
                options.CounterMacAlgorithm = HybridAlgorithmHelper.MacAlgorithm?.Name;
                options.RequireCounterMac = options.CounterMacAlgorithm != null;
            }
            return options;
        }

        /// <summary>
        /// Enable creating a MAC
        /// </summary>
        /// <param name="options">Options</param>
        /// <param name="algo">Algorithm value</param>
        /// <param name="included">Included in the header?</param>
        /// <param name="forceCoverWhole">Force the MAC to cover the whole data?</param>
        /// <returns>Options</returns>
        public static CryptoOptions WithMac(this CryptoOptions options, int algo, bool included = true, bool forceCoverWhole = false)
            => WithMac(options, MacHelper.GetAlgorithm(algo).Name, included, forceCoverWhole);

        /// <summary>
        /// Enable creating a counter MAC
        /// </summary>
        /// <param name="options">Options</param>
        /// <param name="algo">Algorithm name</param>
        /// <returns>Options</returns>
        public static CryptoOptions WithCounterMac(this CryptoOptions options, string? algo = null)
        {
            if (!options.MacIncluded) throw new InvalidOperationException("MAC needs to be included in order to set counter MAC options");
            algo ??= HybridAlgorithmHelper.MacAlgorithm?.Name ?? MacHelper.DefaultAlgorithm.Name;
            MacHelper.GetAlgorithm(algo);
            options.CounterMacAlgorithm = algo;
            options.RequireCounterMac = true;
            return options;
        }

        /// <summary>
        /// Enable creating a counter MAC
        /// </summary>
        /// <param name="options">Options</param>
        /// <param name="algo">Algorithm value</param>
        /// <returns>Options</returns>
        public static CryptoOptions WithCounterMac(this CryptoOptions options, int algo)
            => WithCounterMac(options, MacHelper.GetAlgorithm(algo).Name);

        /// <summary>
        /// Disable creating a MAC
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>Options</returns>
        public static CryptoOptions WithoutMac(this CryptoOptions options)
        {
            options.MacAlgorithm = null;
            options.MacIncluded = false;
            options.MacAlgorithmIncluded = false;
            options.ForceMacCoverWhole = false;
            options.RequireMac = false;
            options.RequireMacCoverWhole = false;
            options.CounterMacAlgorithm = null;
            options.RequireCounterMac = false;
            return options;
        }

        /// <summary>
        /// Enable stretching the encryption password using KDF
        /// </summary>
        /// <param name="options">Options</param>
        /// <param name="algo">Algorithm name</param>
        /// <param name="iterations">Iterations</param>
        /// <param name="included">Included in the header?</param>
        /// <returns>Options</returns>
        public static CryptoOptions WithKdf(this CryptoOptions options, string? algo = null, int? iterations = null, bool included = true)
        {
            algo ??= KdfHelper.DefaultAlgorithm.Name;
            KdfAlgorithmBase kdf = KdfHelper.GetAlgorithm(algo);
            iterations ??= kdf.DefaultIterations;
            options.KdfAlgorithm = algo;
            options.KdfIterations = iterations.Value;
            options.KdfAlgorithmIncluded = included;
            options.RequireKdf = true;
            if (EncryptionHelper.UseHybridOptions && options.CounterKdfAlgorithm == null)
            {
                options.CounterKdfAlgorithm = HybridAlgorithmHelper.KdfAlgorithm?.Name;
                if (options.CounterKdfAlgorithm != null)
                {
                    options.CounterKdfIterations = KdfHelper.GetAlgorithm(options.CounterKdfAlgorithm).DefaultIterations;
                    options.RequireCounterKdf = true;
                }
                else
                {
                    options.CounterKdfIterations = 1;
                    options.RequireCounterKdf = false;
                }
            }
            return options;
        }

        /// <summary>
        /// Enable stretching the encryption password using KDF
        /// </summary>
        /// <param name="options">Options</param>
        /// <param name="algo">Algorithm value</param>
        /// <param name="iterations">Iterations</param>
        /// <param name="included">Included in the header?</param>
        /// <returns>Options</returns>
        public static CryptoOptions WithKdf(this CryptoOptions options, int algo, int? iterations = null, bool included = true)
            => WithKdf(options, KdfHelper.GetAlgorithm(algo).Name, iterations, included);

        /// <summary>
        /// Enable a counter KDF algorithm
        /// </summary>
        /// <param name="options">Options</param>
        /// <param name="algo">Algorithm name</param>
        /// <param name="iterations">Iterations</param>
        /// <returns>Options</returns>
        public static CryptoOptions WithCounterKdf(this CryptoOptions options, string? algo = null, int? iterations = null)
        {
            algo ??= HybridAlgorithmHelper.KdfAlgorithm?.Name ?? KdfHelper.DefaultAlgorithm.Name;
            KdfAlgorithmBase kdf = KdfHelper.GetAlgorithm(algo);
            iterations ??= kdf.DefaultIterations;
            options.CounterKdfAlgorithm = algo;
            options.CounterKdfIterations = iterations.Value;
            options.RequireCounterKdf = true;
            return options;
        }

        /// <summary>
        /// Enable a counter KDF algorithm
        /// </summary>
        /// <param name="options">Options</param>
        /// <param name="algo">Algorithm value</param>
        /// <param name="iterations">Iterations</param>
        /// <returns>Options</returns>
        public static CryptoOptions WithCounterKdf(this CryptoOptions options, int algo, int? iterations = null)
            => WithCounterKdf(options, algo, iterations);

        /// <summary>
        /// Remove KDF options
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>Options</returns>
        public static CryptoOptions WithoutKdf(this CryptoOptions options)
        {
            options.KdfAlgorithm = null;
            options.KdfIterations = 1;
            options.KdfAlgorithmIncluded = false;
            options.RequireKdf = false;
            options.CounterKdfAlgorithm = null;
            options.CounterKdfIterations = 1;
            options.RequireCounterKdf = false;
            return options;
        }

        /// <summary>
        /// Enable PFS key encryption
        /// </summary>
        /// <param name="options">Options</param>
        /// <param name="key">Private key</param>
        /// <param name="peerKey">Peer public key</param>
        /// <returns>Options</returns>
        public static CryptoOptions WithPfs(this CryptoOptions options, IKeyExchangePrivateKey key, IAsymmetricPublicKey? peerKey = null)
        {
            options.SetKeys(key, peerKey);
            return options;
        }

        /// <summary>
        /// Enable a counter key exchange for PFS key encryption
        /// </summary>
        /// <param name="options">Options</param>
        /// <param name="key">Private key</param>
        /// <param name="peerKey">Peer public key</param>
        /// <returns>Options</returns>
        public static CryptoOptions WithCounterKeyExchange(this CryptoOptions options, IKeyExchangePrivateKey key, IAsymmetricPublicKey? peerKey = null)
        {
            options.SetCounterKeys(key, peerKey);
            return options;
        }

        /// <summary>
        /// Set a key exchange algorithm
        /// </summary>
        /// <param name="options">Options</param>
        /// <param name="algo">Algorithm name</param>
        /// <param name="keySize">Key size in bits</param>
        /// <returns>Options</returns>
        public static CryptoOptions WithKeyExchangeAlgorithm(this CryptoOptions options, string? algo = null, int? keySize = null)
        {
            algo ??= AsymmetricHelper.DefaultKeyExchangeAlgorithm.Name;
            IAsymmetricAlgorithm aa = AsymmetricHelper.GetAlgorithm(algo);
            if (!aa.CanExchangeKey) throw new ArgumentException("Algorithm can't key exchange", nameof(algo));
            keySize ??= aa.DefaultKeySize;
            options.AsymmetricAlgorithm = algo;
            options.AsymmetricKeyBits = keySize.Value;
            return options;
        }

        /// <summary>
        /// Set a key exchange algorithm
        /// </summary>
        /// <param name="options">Options</param>
        /// <param name="algo">Algorithm value</param>
        /// <param name="keySize">Key size in bits</param>
        /// <returns>Options</returns>
        public static CryptoOptions WithKeyExchangeAlgorithm(this CryptoOptions options, int algo, int? keySize = null)
            => WithKeyExchangeAlgorithm(options, AsymmetricHelper.GetAlgorithm(algo).Name, keySize);

        /// <summary>
        /// Set a signture algorithm
        /// </summary>
        /// <param name="options">Options</param>
        /// <param name="algo">Algorithm name</param>
        /// <param name="keySize">Key size in bits</param>
        /// <returns>Options</returns>
        public static CryptoOptions WithSignatureAlgorithm(this CryptoOptions options, string? algo = null, int? keySize = null)
        {
            algo ??= AsymmetricHelper.DefaultKeyExchangeAlgorithm.Name;
            IAsymmetricAlgorithm aa = AsymmetricHelper.GetAlgorithm(algo);
            if (!aa.CanSign) throw new ArgumentException("Algorithm can't sign", nameof(algo));
            keySize ??= aa.DefaultKeySize;
            options.AsymmetricAlgorithm = algo;
            options.AsymmetricKeyBits = keySize.Value;
            return options;
        }

        /// <summary>
        /// Set a signture algorithm
        /// </summary>
        /// <param name="options">Options</param>
        /// <param name="algo">Algorithm value</param>
        /// <param name="keySize">Key size in bits</param>
        /// <returns>Options</returns>
        public static CryptoOptions WithSignatureAlgorithm(this CryptoOptions options, int algo, int? keySize = null)
            => WithSignatureAlgorithm(options, AsymmetricHelper.GetAlgorithm(algo).Name, keySize);

        /// <summary>
        /// Set the signature key
        /// </summary>
        /// <param name="options">Options</param>
        /// <param name="key">Private key</param>
        /// <param name="counterKey">Counter signature private key</param>
        /// <returns>Options</returns>
        public static CryptoOptions WithSignatureKey(this CryptoOptions options, ISignaturePrivateKey key, ISignaturePrivateKey? counterKey = null)
        {
            options.SetKeys(key);
            if (counterKey != null) options.SetCounterKeys(counterKey);
            return options;
        }

        /// <summary>
        /// Set the counter signature key
        /// </summary>
        /// <param name="options">Options</param>
        /// <param name="key">Private key</param>
        /// <returns>Options</returns>
        public static CryptoOptions WithCounterSignature(this CryptoOptions options, ISignaturePrivateKey key)
        {
            if (options.PrivateKey == null) throw new InvalidOperationException("Sinature key needs to be set befre setting a counter signature key");
            options.SetCounterKeys(key);
            return options;
        }

        /// <summary>
        /// Remove asymmetric algorithm options
        /// </summary>
        /// <param name="options">Options</param>
        /// <param name="removeKeys">Remove keys?</param>
        /// <returns>Options</returns>
        public static CryptoOptions WithoutAsymmetricAlgorithm(this CryptoOptions options, bool removeKeys = true)
        {
            if (removeKeys)
            {
                options.PrivateKey = null;
                options.PublicKey = null;
            }
            options.AsymmetricAlgorithm = null;
            options.AsymmetricKeyBits = 1;
            options.KeyExchangeDataIncluded = false;
            options.RequireKeyExchangeData = false;
            if (removeKeys)
            {
                options.CounterPrivateKey = null;
                options.CounterPublicKey = null;
            }
            options.AsymmetricCounterAlgorithm = null;
            options.RequireAsymmetricCounterAlgorithm = false;
            return options;
        }

        /// <summary>
        /// Add a payload object
        /// </summary>
        /// <typeparam name="T">Payload type</typeparam>
        /// <param name="options">Options</param>
        /// <param name="payload">Payload</param>
        /// <returns>Options</returns>
        public static CryptoOptions WithPayload<T>(this CryptoOptions options, T payload) where T : notnull
        {
            options.SetPayload(payload);
            return options;
        }

        /// <summary>
        /// Remove payload
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>Options</returns>
        public static CryptoOptions WithoutPayload(this CryptoOptions options)
        {
            options.PayloadData = null;
            return options;
        }

        /// <summary>
        /// Add a hash algorithm
        /// </summary>
        /// <param name="options">Options</param>
        /// <param name="algo">Algorithm name</param>
        /// <returns>Options</returns>
        public static CryptoOptions WithHashAlgorithm(this CryptoOptions options, string? algo = null)
        {
            algo ??= HashHelper.DefaultAlgorithm.Name;
            HashHelper.GetAlgorithm(algo);
            options.HashAlgorithm = algo;
            return options;
        }

        /// <summary>
        /// Add a hash algorithm
        /// </summary>
        /// <param name="options">Options</param>
        /// <param name="algo">Algorithm value</param>
        /// <returns>Options</returns>
        public static CryptoOptions WithHashAlgorithm(this CryptoOptions options, int algo)
            => WithHashAlgorithm(options, HashHelper.GetAlgorithm(algo).Name);

        /// <summary>
        /// Remove the hash algorithm
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>Options</returns>
        public static CryptoOptions WithoutHashAlgorithm(this CryptoOptions options)
        {
            options.HashAlgorithm = null;
            return options;
        }

        /// <summary>
        /// Set the <see cref="CryptoOptions.LeaveOpen"/> value
        /// </summary>
        /// <param name="options">Options</param>
        /// <param name="leaveOpen">Leave the target stream open?</param>
        /// <returns>Options</returns>
        public static CryptoOptions SetLeaveOpen(this CryptoOptions options, bool leaveOpen = true)
        {
            options.LeaveOpen = leaveOpen;
            return options;
        }

        /// <summary>
        /// Remove processing options (get clean options for the next processing (clear the instance))
        /// </summary>
        /// <param name="options">Options</param>
        /// <param name="unsetKeys">Unset keys?</param>
        /// <returns>Options</returns>
        public static CryptoOptions WithoutProcessingData(this CryptoOptions options, bool unsetKeys = true)
        {
            options.Clear(unsetKeys);
            return options;
        }

        /// <summary>
        /// Enable including flags in the header
        /// </summary>
        /// <param name="options">Options</param>
        /// <param name="flags">Flags</param>
        /// <param name="setRequirements">Set the requirements, too?</param>
        /// <returns>Options</returns>
        public static CryptoOptions WithFlagsIncluded(this CryptoOptions options, CryptoFlags? flags = null, bool setRequirements = true)
        {
            options.FlagsIncluded = true;
            if (flags != null)
            {
                options.Flags = flags.Value;
                if (setRequirements) options.Requirements = flags.Value;
            }
            return options;
        }

        /// <summary>
        /// Exclude flagsfrom the header
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>Options</returns>
        public static CryptoOptions WithoutFlagsIncluded(this CryptoOptions options)
        {
            options.FlagsIncluded = false;
            return options;
        }

        /// <summary>
        /// Add additional crypto flags
        /// </summary>
        /// <param name="options">Options</param>
        /// <param name="flags">Flags</param>
        /// <returns>Options</returns>
        public static CryptoOptions WithAdditionalFlags(this CryptoOptions options, params CryptoFlags[] flags)
        {
            CryptoFlags f = options.Flags;
            foreach (CryptoFlags flag in flags) f |= flag;
            options.Flags = f;
            return options;
        }

        /// <summary>
        /// Remove flags
        /// </summary>
        /// <param name="options">Options</param>
        /// <param name="flags">Flags</param>
        /// <returns>Options</returns>
        public static CryptoOptions WithoutFlags(this CryptoOptions options, params CryptoFlags[] flags)
        {
            CryptoFlags f = options.Flags;
            foreach (CryptoFlags flag in flags) f &= ~flag;
            options.Flags = f;
            return options;
        }

        /// <summary>
        /// Set requirements
        /// </summary>
        /// <param name="options">Options</param>
        /// <param name="flags">Flags</param>
        /// <returns>Options</returns>
        public static CryptoOptions WithRequirements(this CryptoOptions options, params CryptoFlags[] flags)
        {
            CryptoFlags f = CryptoFlags.Version1;
            foreach (CryptoFlags flag in flags) f |= flag;
            options.Requirements = f;
            return options;
        }

        /// <summary>
        /// Add additional requirement flags
        /// </summary>
        /// <param name="options">Options</param>
        /// <param name="flags">Flags</param>
        /// <returns>Options</returns>
        public static CryptoOptions WithAdditionalRequirements(this CryptoOptions options, params CryptoFlags[] flags)
        {
            CryptoFlags f = options.Requirements;
            foreach (CryptoFlags flag in flags) f |= flag;
            options.Requirements = f;
            return options;
        }

        /// <summary>
        /// Remove requirement flags
        /// </summary>
        /// <param name="options">Options</param>
        /// <param name="flags">Flags</param>
        /// <returns>Options</returns>
        public static CryptoOptions WithoutRequirements(this CryptoOptions options, params CryptoFlags[] flags)
        {
            CryptoFlags f = options.Requirements;
            foreach (CryptoFlags flag in flags) f &= ~flag;
            options.Requirements = f;
            return options;
        }

        /// <summary>
        /// Include the header version into the header
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>Options</returns>
        public static CryptoOptions WithHeaderVersion(this CryptoOptions options)
        {
            options.HeaderVersionIncluded = true;
            options.RequireHeaderVersion = true;
            return options;
        }

        /// <summary>
        /// Exclude the header version from the header
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>Options</returns>
        public static CryptoOptions WithoutHeaderVersion(this CryptoOptions options)
        {
            options.HeaderVersionIncluded = false;
            options.RequireHeaderVersion = false;
            return options;
        }

        /// <summary>
        /// Include the serializer version into the header
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>Options</returns>
        public static CryptoOptions WithSerializerVersion(this CryptoOptions options)
        {
            options.SerializerVersionIncluded = true;
            options.RequireSerializerVersion = true;
            return options;
        }

        /// <summary>
        /// Exclude the serializer version from the header
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>Options</returns>
        public static CryptoOptions WithoutSerializerVersion(this CryptoOptions options)
        {
            options.SerializerVersionIncluded = false;
            options.RequireSerializerVersion = false;
            return options;
        }
    }
}
