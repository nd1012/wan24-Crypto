using System.ComponentModel.DataAnnotations;
using wan24.Compression;
using wan24.Core;
using wan24.ObjectValidation;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto
{
    /// <summary>
    /// Crypto options
    /// </summary>
    public sealed partial class CryptoOptions : StreamSerializerBase
    {
        /// <summary>
        /// Object version
        /// </summary>
        public const int VERSION = 1;
        /// <summary>
        /// Header version
        /// </summary>
        public const int HEADER_VERSION = 1;

        /// <summary>
        /// Constructor
        /// </summary>
        public CryptoOptions() : base(VERSION) { }

        /// <summary>
        /// Default maximum age
        /// </summary>
        public static TimeSpan? DefaultMaximumAge { get; set; }

        /// <summary>
        /// Default maximum time offset
        /// </summary>
        public static TimeSpan? DefaultMaximumTimeOffset { get; set; }

        /// <summary>
        /// Crypto header data structure version
        /// </summary>
        [Range(1, HEADER_VERSION)]
        public int HeaderVersion { get; set; } = HEADER_VERSION;

        /// <summary>
        /// Serializer version
        /// </summary>
        [Range(1, byte.MaxValue)]
        public int? SerializerVersion { get; set; }

        /// <summary>
        /// Compression options
        /// </summary>
        public CompressionOptions? Compression { get; set; }

        /// <summary>
        /// Encryption algorithm name
        /// </summary>
        [StringLength(byte.MaxValue)]
        public string? Algorithm { get; set; }

        /// <summary>
        /// MAC algorithm name
        /// </summary>
        [StringLength(byte.MaxValue)]
        public string? MacAlgorithm { get; set; }

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
        /// Private key (for en-/decryption/key exchange/signature)
        /// </summary>
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
        public bool LeaveOpen { get; set; } = false;

        /// <summary>
        /// Set the payload
        /// </summary>
        /// <typeparam name="T">Payload type</typeparam>
        /// <param name="payload">Payload</param>
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
                throw new CryptographicException(ex.Message, ex);
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
                if (PayloadData == null) return default(T?);
                if (typeof(IStreamSerializer).IsAssignableFrom(typeof(T)))
                {
                    using MemoryStream ms = new();
                    return (T)ms.ReadAny(serializerVersion);
                }
                else
                {
                    JsonObjectWrapper? wrapper = JsonHelper.Decode<JsonObjectWrapper>(PayloadData.ToUtf8String());
                    if (wrapper == null) throw new InvalidDataException("Failed to deserialize JSON object wrapper");
                    return wrapper.GetHostedObject<T>();
                }
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
        /// Set the keys (used for en-/decryption and signature only)
        /// </summary>
        /// <param name="privateKey">Private key</param>
        /// <param name="publicKey">Public key (required for encryption, if not using a PFS key)</param>
        public void SetKeys(IAsymmetricPrivateKey privateKey, IAsymmetricPublicKey? publicKey = null)
        {
            if (publicKey != null && publicKey.Algorithm != privateKey.Algorithm) throw new ArgumentException("Algorithm mismatch", nameof(publicKey));
            PrivateKey = privateKey;
            PublicKey = publicKey;
            AsymmetricAlgorithm = privateKey.Algorithm.Name;
            KeyExchangeDataIncluded = true;
            RequireKeyExchangeData = true;
        }

        /// <summary>
        /// Set the key exchange data
        /// </summary>
        /// <returns>Key</returns>
        public byte[] SetKeyExchangeData()
        {
            try
            {
                if (PrivateKey is not IKeyExchangePrivateKey key) throw new InvalidOperationException("Missing valid private key exchange key");
                AsymmetricAlgorithm = PrivateKey.Algorithm.Name;
                AsymmetricAlgorithm = key.Algorithm.Name;
                (Password, byte[] kex) = key.GetKeyExchangeData(PublicKey, options: this);
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
                throw new CryptographicException(ex.Message, ex);
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
                if (KeyExchangeData == null) throw new InvalidOperationException("No key exchange data");
                if (UsingAsymmetricCounterAlgorithm)
                {
                    HybridAlgorithmHelper.DeriveKey(KeyExchangeData, this);
                }
                else
                {
                    Password = key.DeriveKey(KeyExchangeData.KeyExchangeData);
                }
                return Password!;
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
            KdfSalt?.Clear();
            KeyExchangeData = null;
            CounterKdfSalt?.Clear();
            PayloadData?.Clear();
            Mac?.Clear();
            Password?.Clear();
        }

        /// <summary>
        /// Get a clone
        /// </summary>
        /// <returns>Clone</returns>
        public CryptoOptions Clone() => new()
        {
            // Algorithms and data
            SerializerVersion = SerializerVersion,
            Compression = Compression?.Clone(),
            Algorithm = Algorithm,
            MacAlgorithm = MacAlgorithm,
            KdfAlgorithm = KdfAlgorithm,
            KdfIterations = KdfIterations,
            AsymmetricAlgorithm = AsymmetricAlgorithm,
            KeyExchangeData = KeyExchangeData?.Clone(),
            CounterMacAlgorithm = CounterMacAlgorithm,
            CounterKdfAlgorithm = CounterKdfAlgorithm,
            CounterKdfIterations = CounterKdfIterations,
            AsymmetricCounterAlgorithm = AsymmetricCounterAlgorithm,
            PayloadData = (byte[]?)PayloadData?.Clone(),
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
            CounterMac = CounterMac,
            HeaderProcessed = HeaderProcessed,
            Password = (byte[]?)Password?.Clone(),
            KdfSalt = (byte[]?)KdfSalt?.Clone(),
            CounterKdfSalt = (byte[]?)CounterKdfSalt?.Clone(),
            PrivateKey = PrivateKey,
            CounterPrivateKey = CounterPrivateKey,
            PublicKey = PublicKey,
            CounterPublicKey = CounterPublicKey,
            LeaveOpen = LeaveOpen
        };
    }
}
