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
        public int KdfIterations { get; set; } = 1;

        /// <summary>
        /// Asymmetric algorithm name (for the key exchange data)
        /// </summary>
        [StringLength(byte.MaxValue)]
        public string? AsymmetricAlgorithm { get; set; }

        /// <summary>
        /// Asymmetric key bits
        /// </summary>
        [Range(1, int.MaxValue)]
        public int AsymmetricKeyBits { get; set; } = AsymmetricEcDiffieHellmanAlgorithm.DEFAULT_KEY_SIZE;

        /// <summary>
        /// Private key
        /// </summary>
        public IAsymmetricPrivateKey? PrivateKey { get; set; }

        /// <summary>
        /// Key exchange data
        /// </summary>
        [CountLimit(ushort.MaxValue)]
        public byte[]? KeyExchangeData { get; set; }

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
                using MemoryStream ms = new();
                ms.WriteAny(payload);
                PayloadData = ms.ToArray();
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
                using MemoryStream ms = new();
                return (T)ms.ReadAny(serializerVersion);
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
        /// Set the private key
        /// </summary>
        /// <param name="key">Private key</param>
        public void SetPrivateKey(IAsymmetricPrivateKey key)
        {
            PrivateKey = key;
            KeyExchangeDataIncluded = true;
            RequireKeyExchangeData = true;
        }

        /// <summary>
        /// Set the PFS key exchange data
        /// </summary>
        /// <param name="key">Private key</param>
        /// <returns>PFS key</returns>
        public byte[] SetKeyExchangeData(IKeyExchangePrivateKey? key = null)
        {
            try
            {
                key ??= PrivateKey as IKeyExchangePrivateKey ?? throw new ArgumentNullException(nameof(key));
                AsymmetricAlgorithm = key.Algorithm;
                using (IKeyExchangePrivateKey pfsKey = (AsymmetricHelper.GetAlgorithm(key.Algorithm).CreateKeyPair(new()
                {
                    AsymmetricKeyBits = key.Bits
                }) as IKeyExchangePrivateKey)!)
                    KeyExchangeData = pfsKey.GetKeyExchangeData(this);
                if (UsingAsymmetricCounterAlgorithm)
                {
                    byte[] kex = KeyExchangeData;
                    try
                    {
                        KeyExchangeData = HybridAlgorithmHelper.GetKeyExchangeData(kex, this);
                    }
                    finally
                    {
                        kex.Clear();
                    }
                }
                KeyExchangeDataIncluded = true;
                return UsingAsymmetricCounterAlgorithm
                    ? HybridAlgorithmHelper.DeriveKey(KeyExchangeData, this)
                    : key.DeriveKey(KeyExchangeData);
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
        /// Derive the exchanged PFS key
        /// </summary>
        /// <param name="key">Private key</param>
        /// <returns>PFS key</returns>
        public byte[] DeriveExchangedKey(IKeyExchangePrivateKey? key = null)
        {
            try
            {
                key ??= PrivateKey as IKeyExchangePrivateKey ?? throw new ArgumentNullException(nameof(key));
                if (KeyExchangeData == null) throw new InvalidOperationException("No key exchange data");
                if (AsymmetricAlgorithmIncluded)
                {
                    if (AsymmetricAlgorithm == null) throw new InvalidOperationException("Missing asymmetric algorithm name");
                    if (AsymmetricAlgorithm != key.Algorithm) throw new ArgumentException("Private key algorithm mismatch");
                }
                return UsingAsymmetricCounterAlgorithm
                    ? HybridAlgorithmHelper.DeriveKey(KeyExchangeData, this)
                    : key.DeriveKey(KeyExchangeData);
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
        /// <param name="unsetPrivateKey">Unset the private key?</param>
        public void Clear(bool unsetPrivateKey = true)
        {
            HeaderProcessed = false;
            if (unsetPrivateKey)
            {
                PrivateKey = null;
                CounterPrivateKey = null;
            }
            KdfSalt?.Clear();
            KeyExchangeData?.Clear();
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
            KeyExchangeData = (byte[]?)KeyExchangeData?.Clone(),
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
            LeaveOpen = LeaveOpen
        };
    }
}
