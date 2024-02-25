using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;
using wan24.Compression;
using wan24.Core;
using wan24.ObjectValidation;
using wan24.StreamSerializerExtensions;

//TODO Use MemberNotNull

namespace wan24.Crypto
{
    /// <summary>
    /// Crypto options
    /// </summary>
    public sealed partial record class CryptoOptions : StreamSerializerRecordBase, ICloneable
    {
        /// <summary>
        /// Object version
        /// </summary>
        public const int VERSION = 3;
        /// <summary>
        /// Header version
        /// </summary>
        public const int HEADER_VERSION = 1;

        /// <summary>
        /// Constructor
        /// </summary>
        public CryptoOptions() : this(raiseEvent: true) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="raiseEvent">Raise the <see cref="OnInstanced"/> event?</param>
        private CryptoOptions(bool raiseEvent) : base(VERSION)
        {
            Requirements = Flags = DefaultFlags;
            RequirePrivateKeyRevision = DefaultPrivateKeysStore is not null;
            PrivateKeyRevisionIncluded = DefaultPrivateKeysStore is not null;
            if (raiseEvent) OnInstanced?.Invoke(this, new());
        }

        /// <summary>
        /// Default maximum age
        /// </summary>
        public static TimeSpan? DefaultMaximumAge { get; set; }

        /// <summary>
        /// Default maximum time offset
        /// </summary>
        public static TimeSpan? DefaultMaximumTimeOffset { get; set; }

        /// <summary>
        /// Default private key suite store
        /// </summary>
        public static PrivateKeySuiteStore? DefaultPrivateKeysStore { get; set; }

        /// <summary>
        /// Default flags (will be used for requirements, too)
        /// </summary>
        public static CryptoFlags DefaultFlags { get; set; }
            = CryptoFlags.LatestVersion | 
                CryptoFlags.SerializerVersionIncluded | 
                CryptoFlags.HeaderVersionIncluded | 
                CryptoFlags.MacIncluded | 
                CryptoFlags.KdfAlgorithmIncluded | 
                CryptoFlags.Compressed;

        /// <summary>
        /// Default for <see cref="FlagsIncluded"/>
        /// </summary>
        public static bool DefaultFlagsIncluded { get; set; } = true;

        /// <summary>
        /// Default encryption password pre-processor
        /// </summary>
        public static EncryptionPasswordPreProcessor_Delegate? DefaultEncryptionPasswordPreProcessor { get; set; }

        /// <summary>
        /// Default encryption password pre-processor (only applied during asynchronous operation)
        /// </summary>
        public static AsyncEncryptionPasswordPreProcessor_Delegate? DefaultEncryptionPasswordAsyncPreProcessor { get; set; }

        /// <summary>
        /// Crypto header data structure version
        /// </summary>
        [Range(1, HEADER_VERSION)]
        public int HeaderVersion { get; set; } = HEADER_VERSION;

        /// <summary>
        /// Custom serializer version
        /// </summary>
        [Range(1, byte.MaxValue)]
        public int? CustomSerializerVersion { get; set; }

        /// <summary>
        /// Compression options
        /// </summary>
        public CompressionOptions? Compression { get; set; }

        /// <summary>
        /// Maximum uncompressed data length in bytes (or <c>-1</c> for no limit)
        /// </summary>
        [Range(-1, long.MaxValue)]
        public long MaxUncompressedDataLength { get; set; } = -1;

        /// <summary>
        /// Encryption algorithm name
        /// </summary>
        [StringLength(byte.MaxValue)]
        public string? Algorithm { get; set; }

        /// <summary>
        /// Encryption options
        /// </summary>
        [StringLength(byte.MaxValue)]
        public string? EncryptionOptions { get; set; }

        /// <summary>
        /// Encryption password pre-processor
        /// </summary>
        public EncryptionPasswordPreProcessor_Delegate? EncryptionPasswordPreProcessor { get; set; } = DefaultEncryptionPasswordPreProcessor;

        /// <summary>
        /// Encryption password pre-processor (only applied during asynchronous operation)
        /// </summary>
        public AsyncEncryptionPasswordPreProcessor_Delegate? EncryptionPasswordAsyncPreProcessor { get; set; } = DefaultEncryptionPasswordAsyncPreProcessor;

        /// <summary>
        /// MAC algorithm name
        /// </summary>
        [StringLength(byte.MaxValue)]
        public string? MacAlgorithm { get; set; }

        /// <summary>
        /// MAC password
        /// </summary>
        [SensitiveData, CountLimit(short.MaxValue)]
        public byte[]? MacPassword { get; set; }

        /// <summary>
        /// KDF algorithm name
        /// </summary>
        [StringLength(byte.MaxValue)]
        public string? KdfAlgorithm { get; set; }

        /// <summary>
        /// KDF iterations
        /// </summary>
        [Range(1, int.MaxValue)]
        public int KdfIterations { get; set; } = 1;// Dummy value to satisfy the object validation

        /// <summary>
        /// KDF options
        /// </summary>
        [StringLength(byte.MaxValue)]
        public string? KdfOptions { get; set; }

        /// <summary>
        /// Asymmetric algorithm name (for the key exchange data)
        /// </summary>
        [StringLength(byte.MaxValue)]
        public string? AsymmetricAlgorithm { get; set; }

        /// <summary>
        /// Asymmetric key bits
        /// </summary>
        [Range(1, int.MaxValue)]
        public int AsymmetricKeyBits { get; set; } = 1;// Dummy value to satisfy the object validation

        /// <summary>
        /// Asymmetric algorithm options
        /// </summary>
        [StringLength(byte.MaxValue)]
        public string? AsymmetricAlgorithmOptions { get; set; }

        /// <summary>
        /// Private keys store (won't be serialized!)
        /// </summary>
        public PrivateKeySuiteStore? PrivateKeysStore { get; set; } = DefaultPrivateKeysStore;

        /// <summary>
        /// Private key revision
        /// </summary>
        [Range(0, int.MaxValue)]
        public int PrivateKeyRevision { get; set; }

        /// <summary>
        /// Private key (for en-/decryption/key exchange/signature)
        /// </summary>
        [SensitiveData]
        public IAsymmetricPrivateKey? PrivateKey { get; set; }

        /// <summary>
        /// Public key (for encryption/key exchange)
        /// </summary>
        public IAsymmetricPublicKey? PublicKey { get; set; }

        /// <summary>
        /// Key exchange data
        /// </summary>
        public KeyExchangeDataContainer? KeyExchangeData { get; set; }

        /// <summary>
        /// Payload data (won't be encrypted, but included in the MAC)
        /// </summary>
        [CountLimit(ushort.MaxValue)]
        public byte[]? PayloadData { get; set; }

        /// <summary>
        /// Time (UTC)
        /// </summary>
        public DateTime? Time { get; set; }

        /// <summary>
        /// Hash algorithm name
        /// </summary>
        [StringLength(byte.MaxValue)]
        public string? HashAlgorithm { get; set; }

        /// <summary>
        /// Leave the processing stream open?
        /// </summary>
        public bool LeaveOpen { get; set; }

        /// <summary>
        /// Tracer
        /// </summary>
        public Tracer? Tracer { get; set; }

        /// <summary>
        /// RNG seeding flags (to override <see cref="RND.AutoRngSeeding"/>; won't be serialized!)
        /// </summary>
        public RngSeedingTypes? RngSeeding { get; set; }

        /// <summary>
        /// Set the payload
        /// </summary>
        /// <typeparam name="T">Payload type</typeparam>
        /// <param name="payload">Payload</param>
        [MemberNotNull(nameof(PayloadData))]
        public void SetPayload<T>(T payload) where T : notnull
        {
            try
            {
                if (typeof(T) is IStreamSerializer)
                {
                    using MemoryStream ms = new();
                    ms.WriteAny(payload);
                    PayloadData = ms.ToArray();
                }
                else
                {
                    if (!EncryptionHelper.EnableJsonWrapper) throw new InvalidOperationException("JSON object wrapper disabled");
                    PayloadData = JsonHelper.Encode(new JsonObjectWrapper(payload)).GetBytes();
                }
                PayloadIncluded = true;
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
        /// Get the payload
        /// </summary>
        /// <typeparam name="T">Payload type</typeparam>
        /// <param name="serializerVersion">Serializer version</param>
        /// <returns>Payload</returns>
        public T? GetPayload<T>(int? serializerVersion = null)
        {
            try
            {
#pragma warning disable IDE0034 // default expression can be simplified
                if (PayloadData is null) return default(T?);
#pragma warning restore IDE0034
                serializerVersion ??= CustomSerializerVersion;
                if (typeof(IStreamSerializer).IsAssignableFrom(typeof(T)))
                {
                    using MemoryStream ms = new();
                    return (T)ms.ReadAny(serializerVersion);
                }
                else
                {
                    if (!EncryptionHelper.EnableJsonWrapper) throw new InvalidOperationException("JSON object wrapper disabled");
                    JsonObjectWrapper wrapper = JsonHelper.Decode<JsonObjectWrapper>(PayloadData.ToUtf8String()) ?? throw new InvalidDataException("Failed to deserialize JSON object wrapper");
                    return wrapper.GetHostedObject<T>();
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
        /// Set a new encryption password (will clear the old value, if any)
        /// </summary>
        /// <param name="pwd">New password (won't be cloned!)</param>
        [MemberNotNull(nameof(Password))]
        public void SetNewPassword(in byte[] pwd)
        {
            Password?.Clear();
            Password = pwd;
        }

        /// <summary>
        /// Set a new MAC password (will clear the old value, if any)
        /// </summary>
        /// <param name="pwd">New password (won't be cloned!)</param>
        [MemberNotNull(nameof(MacPassword))]
        public void SetNewMacPassword(in byte[] pwd)
        {
            MacPassword?.Clear();
            MacPassword = pwd;
        }

        /// <summary>
        /// Set the keys (used for en-/decryption and signature only)
        /// </summary>
        /// <param name="privateKey">Private key</param>
        /// <param name="publicKey">Public key (required for encryption, if not using a PFS key)</param>
        [MemberNotNull(nameof(PrivateKey), nameof(AsymmetricAlgorithm))]
        public void SetKeys(IAsymmetricPrivateKey privateKey, IAsymmetricPublicKey? publicKey = null)
        {
            try
            {
                PrivateKey = privateKey;
                if (publicKey is not null) PublicKey = publicKey;
                if (PublicKey is not null && PublicKey.Algorithm != privateKey.Algorithm) throw new ArgumentException("Algorithm mismatch", nameof(publicKey));
                AsymmetricAlgorithm = privateKey.Algorithm.Name;
                KeyExchangeDataIncluded = true;
                RequireKeyExchangeData = true;
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
        /// Set the key exchange data
        /// </summary>
        /// <returns>Key</returns>
        [MemberNotNull(nameof(KeyExchangeData), nameof(AsymmetricAlgorithm))]
        public byte[] SetKeyExchangeData()
        {
            try
            {
                if (PrivateKey is not IKeyExchangePrivateKey key) throw new InvalidOperationException("Missing valid private key exchange key");
                AsymmetricAlgorithm = PrivateKey.Algorithm.Name;
                (byte[] newPwd, byte[] kex) = key.GetKeyExchangeData(PublicKey, options: this);
                SetNewPassword(newPwd);
                KeyExchangeData = new()
                {
                    KeyExchangeData = kex
                };
                if (UsingAsymmetricCounterAlgorithm) HybridAlgorithmHelper.GetKeyExchangeData(KeyExchangeData, this);
                KeyExchangeDataIncluded = true;
                return Password;
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
        /// Derive the exchanged key
        /// </summary>
        /// <returns>Key</returns>
        public byte[] DeriveExchangedKey()
        {
            try
            {
                if (PrivateKey is not IKeyExchangePrivateKey key) throw new InvalidOperationException("Missing or invalid private key");
                if (KeyExchangeData is null) throw new InvalidOperationException("No key exchange data");
                if (UsingAsymmetricCounterAlgorithm)
                {
                    HybridAlgorithmHelper.DeriveKey(KeyExchangeData, this);
                }
                else
                {
                    SetNewPassword(key.DeriveKey(KeyExchangeData.KeyExchangeData));
                }
                return Password!;
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
        /// Clear sensible object data (and reset for re-use)
        /// </summary>
        /// <param name="unsetKeys">Unset the asymmetric keys?</param>
        public void Clear(bool unsetKeys = true)
        {
            HeaderProcessed = false;
            if (unsetKeys)
            {
                PrivateKey = null;
                CounterPrivateKey = null;
                PublicKey = null;
                CounterPublicKey = null;
            }
            if (KdfSalt is not null)
            {
                KdfSalt.Clear();
                KdfSalt = null;
            }
            if (CounterKdfSalt is not null)
            {
                CounterKdfSalt.Clear();
                CounterKdfSalt = null;
            }
            KeyExchangeData = null;
            if (PayloadData is not null)
            {
                PayloadData.Clear();
                PayloadData = null;
            }
            if (Mac is not null)
            {
                Mac.Clear();
                Mac = null;
            }
            if(MacPassword is not null)
            {
                MacPassword.Clear();
                MacPassword = null;
            }
            if (Password is not null)
            {
                Password.Clear();
                Password = null;
            }
        }

        /// <summary>
        /// Get a copy of this instance
        /// </summary>
        /// <returns>Instance copy</returns>
        public CryptoOptions GetCopy() => new(raiseEvent: false)
        {
            // Algorithms and data
            CustomSerializerVersion = CustomSerializerVersion,
            Compression = Compression?.GetCopy(),
            MaxUncompressedDataLength = MaxUncompressedDataLength,
            Algorithm = Algorithm,
            EncryptionOptions = EncryptionOptions,
            EncryptionPasswordPreProcessor = EncryptionPasswordPreProcessor,
            EncryptionPasswordAsyncPreProcessor = EncryptionPasswordAsyncPreProcessor,
            MacAlgorithm = MacAlgorithm,
            MacPassword = MacPassword?.CloneArray(),
            KdfAlgorithm = KdfAlgorithm,
            KdfIterations = KdfIterations,
            KdfOptions = KdfOptions,
            PrivateKeysStore = PrivateKeysStore,
            PrivateKeyRevision = PrivateKeyRevision,
            AsymmetricAlgorithm = AsymmetricAlgorithm,
            AsymmetricAlgorithmOptions = AsymmetricAlgorithmOptions,
            KeyExchangeData = KeyExchangeData?.GetCopy(),
            CounterMacAlgorithm = CounterMacAlgorithm,
            CounterKdfAlgorithm = CounterKdfAlgorithm,
            CounterKdfIterations = CounterKdfIterations,
            CounterKdfOptions = CounterKdfOptions,
            AsymmetricCounterAlgorithm = AsymmetricCounterAlgorithm,
            PayloadData = PayloadData?.CloneArray(),
            Time = Time,
            HashAlgorithm = HashAlgorithm,
            AsymmetricKeyBits = AsymmetricKeyBits,
            // Flags
            FlagsIncluded = FlagsIncluded,
            Flags = Flags,
            // Requirements
            Requirements = Requirements,
            // Other settings
            HeaderVersion = HeaderVersion,
            MaximumAge = MaximumAge,
            MaximumTimeOffset = MaximumTimeOffset,
            MacPosition = MacPosition,
            Mac = Mac,
            HeaderProcessed = HeaderProcessed,
            Password = Password?.CloneArray(),
            KdfSalt = KdfSalt?.CloneArray(),
            CounterKdfSalt = CounterKdfSalt?.CloneArray(),
            PrivateKey = PrivateKey,
            CounterPrivateKey = CounterPrivateKey,
            PublicKey = PublicKey,
            CounterPublicKey = CounterPublicKey,
            LeaveOpen = LeaveOpen,
            Tracer = Tracer,
            RngSeeding = RngSeeding
        };

        /// <inheritdoc/>
        object ICloneable.Clone() => GetCopy();

        /// <summary>
        /// Delegate for an encryption password pre-processor
        /// </summary>
        /// <param name="algo">Encryption algorithm</param>
        /// <param name="options">Options</param>
        public delegate void EncryptionPasswordPreProcessor_Delegate(EncryptionAlgorithmBase algo, CryptoOptions options);

        /// <summary>
        /// Delegate for an encryption password pre-processor
        /// </summary>
        /// <param name="algo">Encryption algorithm</param>
        /// <param name="options">Options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        public delegate Task AsyncEncryptionPasswordPreProcessor_Delegate(EncryptionAlgorithmBase algo, CryptoOptions options, CancellationToken cancellationToken);
    }
}
