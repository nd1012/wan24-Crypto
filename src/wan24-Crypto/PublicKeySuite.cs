using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto
{
    /// <summary>
    /// Public key suite
    /// </summary>
    public sealed class PublicKeySuite : DisposableBase, IStreamSerializerVersion, ICloneable
    {
        /// <summary>
        /// Object version
        /// </summary>
        public const int VERSION = 1;

        /// <summary>
        /// Serialized object version
        /// </summary>
        private int? _SerializedObjectVersion = null;
        /// <summary>
        /// Key exchange public key
        /// </summary>
        private IAsymmetricPublicKey? _KeyExchangeKey = null;
        /// <summary>
        /// Counter key exchange public key
        /// </summary>
        private IAsymmetricPublicKey? _CounterKeyExchangeKey = null;

        /// <summary>
        /// Constructor
        /// </summary>
        public PublicKeySuite() : base() { }

        /// <summary>
        /// Key exchange key (will be disposed)
        /// </summary>
        public IAsymmetricPublicKey? KeyExchangeKey
        {
            get => _KeyExchangeKey;
            set
            {
                EnsureUndisposed();
                if (value != null && !value.Algorithm.CanExchangeKey) throw new ArgumentException("Key can't key exchange", nameof(value));
                _KeyExchangeKey = value;
            }
        }

        /// <summary>
        /// Counter key exchange key (will be disposed)
        /// </summary>
        public IAsymmetricPublicKey? CounterKeyExchangeKey
        {
            get => _CounterKeyExchangeKey;
            set
            {
                EnsureUndisposed();
                if (value != null && !value.Algorithm.CanExchangeKey) throw new ArgumentException("Key can't key exchange", nameof(value));
                _CounterKeyExchangeKey = value;
            }
        }

        /// <summary>
        /// Signature public key (will be disposed)
        /// </summary>
        public ISignaturePublicKey? SignatureKey { get; set; }

        /// <summary>
        /// Counter signature public key (will be disposed)
        /// </summary>
        public ISignaturePublicKey? CounterSignatureKey { get; set; }

        /// <summary>
        /// Signed public key (will be disposed)
        /// </summary>
        public AsymmetricSignedPublicKey? SignedPublicKey { get; set; }

        /// <inheritdoc/>
        int? IStreamSerializerVersion.ObjectVersion => VERSION;

        /// <inheritdoc/>
        int? IStreamSerializerVersion.SerializedObjectVersion => _SerializedObjectVersion;

        /// <summary>
        /// Clone this public key suite
        /// </summary>
        /// <returns>Clone</returns>
        public PublicKeySuite Clone() => IfUndisposed(() => new PublicKeySuite()
        {
            _KeyExchangeKey = _KeyExchangeKey?.GetCopy(),
            _CounterKeyExchangeKey = _CounterKeyExchangeKey?.GetCopy(),
            SignatureKey = (ISignaturePublicKey?)SignatureKey?.GetCopy(),
            CounterSignatureKey = (ISignaturePublicKey?)CounterSignatureKey?.GetCopy(),
            SignedPublicKey = SignedPublicKey == null ? null : (AsymmetricSignedPublicKey)(byte[])SignedPublicKey
        });

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            _KeyExchangeKey?.Dispose();
            _CounterKeyExchangeKey?.Dispose();
            SignatureKey?.Dispose();
            CounterSignatureKey?.Dispose();
            SignedPublicKey?.Dispose();
        }

        /// <inheritdoc/>
        object ICloneable.Clone() => Clone();

        /// <inheritdoc/>
        public void Serialize(Stream stream)
        {
            EnsureUndisposed();
            stream.WriteNumber(VERSION);
            stream.WriteAnyNullable(_KeyExchangeKey)
                .WriteAnyNullable(_CounterKeyExchangeKey)
                .WriteAnyNullable(SignatureKey)
                .WriteAnyNullable(CounterSignatureKey)
                .WriteSerializedNullable(SignedPublicKey);
        }

        /// <inheritdoc/>
        public async Task SerializeAsync(Stream stream, CancellationToken cancellationToken)
        {
            EnsureUndisposed();
            await stream.WriteNumberAsync(VERSION, cancellationToken).DynamicContext();
            await stream.WriteAnyNullableAsync(_KeyExchangeKey, cancellationToken).DynamicContext();
            await stream.WriteAnyNullableAsync(_CounterKeyExchangeKey, cancellationToken).DynamicContext();
            await stream.WriteAnyNullableAsync(SignatureKey, cancellationToken).DynamicContext();
            await stream.WriteAnyNullableAsync(CounterSignatureKey, cancellationToken).DynamicContext();
            await stream.WriteSerializedNullableAsync(SignedPublicKey, cancellationToken).DynamicContext();
        }

        /// <inheritdoc/>
        public void Deserialize(Stream stream, int version)
        {
            EnsureUndisposed();
            _SerializedObjectVersion = StreamSerializerAdapter.ReadSerializedObjectVersion(stream, version, VERSION);
            _KeyExchangeKey = (IAsymmetricPublicKey?)stream.ReadAnyNullable(version);
            _CounterKeyExchangeKey = (IAsymmetricPublicKey?)stream.ReadAnyNullable(version);
            SignatureKey = (ISignaturePublicKey?)stream.ReadAnyNullable(version);
            CounterSignatureKey = (ISignaturePublicKey?)stream.ReadAnyNullable(version);
            SignedPublicKey = stream.ReadSerializedNullable<AsymmetricSignedPublicKey>(version);
        }

        /// <inheritdoc/>
        public async Task DeserializeAsync(Stream stream, int version, CancellationToken cancellationToken)
        {
            EnsureUndisposed();
            _SerializedObjectVersion = await StreamSerializerAdapter.ReadSerializedObjectVersionAsync(stream, version, VERSION, cancellationToken).DynamicContext();
            _KeyExchangeKey = (IAsymmetricPublicKey?)await stream.ReadAnyNullableAsync(version, cancellationToken).DynamicContext();
            _CounterKeyExchangeKey = (IAsymmetricPublicKey?)await stream.ReadAnyNullableAsync(version, cancellationToken).DynamicContext();
            SignatureKey = (ISignaturePublicKey?)await stream.ReadAnyNullableAsync(version, cancellationToken).DynamicContext();
            CounterSignatureKey = (ISignaturePublicKey?)await stream.ReadAnyNullableAsync(version, cancellationToken).DynamicContext();
            SignedPublicKey = await stream.ReadSerializedNullableAsync<AsymmetricSignedPublicKey>(version, cancellationToken).DynamicContext();
        }

        /// <summary>
        /// Cast as asymmetric signed public key
        /// </summary>
        /// <param name="suite">Public key suite</param>
        public static implicit operator AsymmetricSignedPublicKey(PublicKeySuite suite) => suite.SignedPublicKey ?? throw new InvalidOperationException("No signed public key");

        /// <summary>
        /// Cast as serialized data
        /// </summary>
        /// <param name="suite">Public key suite</param>
        public static implicit operator byte[](PublicKeySuite suite) => suite.ToBytes();

        /// <summary>
        /// Cast from serialized data
        /// </summary>
        /// <param name="data">Data</param>
        public static explicit operator PublicKeySuite(byte[] data) => data.ToObject<PublicKeySuite>();
    }
}
