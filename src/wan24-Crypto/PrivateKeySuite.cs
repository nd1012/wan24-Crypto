using wan24.Core;
using wan24.ObjectValidation;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto
{
    /// <summary>
    /// Private key suite (for storing long term keys)
    /// </summary>
    public sealed class PrivateKeySuite : DisposableStreamSerializerBase, ICloneable
    {
        /// <summary>
        /// Object version
        /// </summary>
        public const int VERSION = 1;

        /// <summary>
        /// Public key suite
        /// </summary>
        private PublicKeySuite? _Public = null;

        /// <summary>
        /// Constructor
        /// </summary>
        public PrivateKeySuite() : base(VERSION) { }

        /// <summary>
        /// Key exchange private key (will be disposed)
        /// </summary>
        public IKeyExchangePrivateKey? KeyExchangeKey { get; set; }

        /// <summary>
        /// Counter key exchange private key (will be disposed)
        /// </summary>
        public IKeyExchangePrivateKey? CounterKeyExchangeKey { get; set; }

        /// <summary>
        /// Signature private key (will be disposed)
        /// </summary>
        public ISignaturePrivateKey? SignatureKey { get; set; }

        /// <summary>
        /// Counter signature private key (will be disposed)
        /// </summary>
        public ISignaturePrivateKey? CounterSignatureKey { get; set; }

        /// <summary>
        /// Signed public key (will be disposed)
        /// </summary>
        public AsymmetricSignedPublicKey? SignedPublicKey { get; set; }

        /// <summary>
        /// Symmetric key (will be cleared)
        /// </summary>
        [SensitiveData, CountLimit(1, byte.MaxValue)]
        public byte[]? SymmetricKey { get; set; }

        /// <summary>
        /// Public key suite (will be disposed when this instance is being disposed)
        /// </summary>
        public PublicKeySuite Public => IfUndisposed(() => _Public ??= new()
        {
            KeyExchangeKey = KeyExchangeKey?.PublicKey.GetCopy(),
            SignatureKey = (ISignaturePublicKey?)SignatureKey?.PublicKey.GetCopy(),
            SignedPublicKey = SignedPublicKey == null ? null : (AsymmetricSignedPublicKey)(byte[])SignedPublicKey
        });

        /// <summary>
        /// Serialize and encrypt this private key suite for physical cold storage
        /// </summary>
        /// <param name="key">Key</param>
        /// <param name="options">Options</param>
        /// <returns>Cipher</returns>
        public byte[] Encrypt(byte[] key, CryptoOptions? options = null) => ((byte[])this).Encrypt(key, options);

        /// <summary>
        /// Create crypto options
        /// </summary>
        /// <returns>Options</returns>
        public CryptoOptions CreateOptions()
        {
            EnsureUndisposed();
            CryptoOptions res = new();
            res.ApplyPrivateKeySuite(this);
            return res;
        }

        /// <summary>
        /// Clone this private key suite
        /// </summary>
        /// <returns>Clone</returns>
        public PrivateKeySuite Clone() => IfUndisposed(() => new PrivateKeySuite()
        {
            _Public = _Public?.Clone(),
            KeyExchangeKey = (IKeyExchangePrivateKey?)KeyExchangeKey?.GetCopy(),
            CounterKeyExchangeKey = (IKeyExchangePrivateKey?)CounterKeyExchangeKey?.GetCopy(),
            SignatureKey = (ISignaturePrivateKey?)SignatureKey?.GetCopy(),
            CounterSignatureKey = (ISignaturePrivateKey?)CounterSignatureKey?.GetCopy(),
            SignedPublicKey = SignedPublicKey == null ? null : (AsymmetricSignedPublicKey)(byte[])SignedPublicKey,
            SymmetricKey = (byte[]?)SymmetricKey?.Clone()
        });

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            _Public?.Dispose();
            KeyExchangeKey?.Dispose();
            CounterKeyExchangeKey?.Dispose();
            SignatureKey?.Dispose();
            CounterSignatureKey?.Dispose();
            SignedPublicKey?.Dispose();
            SymmetricKey?.Clear();
        }

        /// <inheritdoc/>
        object ICloneable.Clone() => Clone();

        /// <inheritdoc/>
        protected override void Serialize(Stream stream)
        {
            stream.WriteAnyNullable(KeyExchangeKey)
                .WriteAnyNullable(CounterKeyExchangeKey)
                .WriteAnyNullable(SignatureKey)
                .WriteAnyNullable(CounterSignatureKey)
                .WriteSerializedNullable(SignedPublicKey)
                .WriteBytesNullable(SymmetricKey);
        }

        /// <inheritdoc/>
        protected override async Task SerializeAsync(Stream stream, CancellationToken cancellationToken)
        {
            await stream.WriteAnyNullableAsync(KeyExchangeKey, cancellationToken).DynamicContext();
            await stream.WriteAnyNullableAsync(CounterKeyExchangeKey, cancellationToken).DynamicContext();
            await stream.WriteAnyNullableAsync(SignatureKey, cancellationToken).DynamicContext();
            await stream.WriteAnyNullableAsync(CounterSignatureKey, cancellationToken).DynamicContext();
            await stream.WriteSerializedNullableAsync(SignedPublicKey, cancellationToken).DynamicContext();
            await stream.WriteBytesNullableAsync(SymmetricKey, cancellationToken).DynamicContext();
        }

        /// <inheritdoc/>
        protected override void Deserialize(Stream stream, int version)
        {
            KeyExchangeKey = (IKeyExchangePrivateKey?)stream.ReadAnyNullable(version);
            CounterKeyExchangeKey = (IKeyExchangePrivateKey?)stream.ReadAnyNullable(version);
            SignatureKey = (ISignaturePrivateKey?)stream.ReadAnyNullable(version);
            CounterSignatureKey = (ISignaturePrivateKey?)stream.ReadAnyNullable(version);
            SignedPublicKey = stream.ReadSerializedNullable<AsymmetricSignedPublicKey>(version);
            SymmetricKey = stream.ReadBytesNullable(version, minLen: 1, maxLen: byte.MaxValue)?.Value;
        }

        /// <inheritdoc/>
        protected override async Task DeserializeAsync(Stream stream, int version, CancellationToken cancellationToken)
        {
            KeyExchangeKey = (IKeyExchangePrivateKey?)await stream.ReadAnyNullableAsync(version, cancellationToken: cancellationToken).DynamicContext();
            CounterKeyExchangeKey = (IKeyExchangePrivateKey?)await stream.ReadAnyNullableAsync(version, cancellationToken: cancellationToken).DynamicContext();
            SignatureKey = (ISignaturePrivateKey?)await stream.ReadAnyNullableAsync(version, cancellationToken: cancellationToken).DynamicContext();
            CounterSignatureKey = (ISignaturePrivateKey?)await stream.ReadAnyNullableAsync(version, cancellationToken: cancellationToken).DynamicContext();
            SignedPublicKey = await stream.ReadSerializedNullableAsync<AsymmetricSignedPublicKey>(version, cancellationToken).DynamicContext();
            SymmetricKey = (await stream.ReadBytesNullableAsync(version, minLen: 1, maxLen: byte.MaxValue, cancellationToken: cancellationToken).DynamicContext())?.Value;
        }

        /// <summary>
        /// Cast as public key suite
        /// </summary>
        /// <param name="suite">Private key suite</param>
        public static implicit operator PublicKeySuite(PrivateKeySuite suite) => suite.Public;

        /// <summary>
        /// Cast as asymmetric signed public key
        /// </summary>
        /// <param name="suite">Private key suite</param>
        public static implicit operator AsymmetricSignedPublicKey(PrivateKeySuite suite) => suite.SignedPublicKey ?? throw new InvalidOperationException("No signed public key");

        /// <summary>
        /// Cast as serialized data
        /// </summary>
        /// <param name="suite">Private key suite</param>
        public static implicit operator byte[](PrivateKeySuite suite) => suite.ToBytes();

        /// <summary>
        /// Cast from serialized data
        /// </summary>
        /// <param name="data">Data</param>
        public static explicit operator PrivateKeySuite(byte[] data) => data.ToObject<PrivateKeySuite>();

        /// <summary>
        /// Create a private key suite with new key exchange, signature and symmetric keys
        /// </summary>
        /// <returns>Private key suite</returns>
        public static PrivateKeySuite Create() => new PrivateKeySuite()
            .WithKeyExchangeKey()
            .WithSignatureKey()
            .WithSymmetricKey();

        /// <summary>
        /// Create a private key suite with new key exchange, signature and symmetric keys (and new counter algorithm keys)
        /// </summary>
        /// <returns>Private key suite</returns>
        public static PrivateKeySuite CreateWithCounterAlgorithms() => new PrivateKeySuite()
            .WithKeyExchangeKey()
            .WithCounterKeyExchangeKey()
            .WithSignatureKey()
            .WithCounterSignatureKey()
            .WithSymmetricKey();

        /// <summary>
        /// Decrypt a private key suite cipher and deserialize to a private key suite instance
        /// </summary>
        /// <param name="cipher">Cipher</param>
        /// <param name="key">Key</param>
        /// <param name="options">Options</param>
        /// <returns>Private key suite</returns>
        public static PrivateKeySuite Decrypt(byte[] cipher, byte[] key, CryptoOptions? options = null) => (PrivateKeySuite)cipher.Decrypt(key, options);
    }
}
