using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto
{
    /// <summary>
    /// Public key suite
    /// </summary>
    public sealed class PublicKeySuite : DisposableStreamSerializerBase, ICloneable
    {
        /// <summary>
        /// Object version
        /// </summary>
        public const int VERSION = 1;

        /// <summary>
        /// Key exchange public key
        /// </summary>
        private IAsymmetricPublicKey? _KeyExchangeKey = null;
        /// <summary>
        /// Counter key exchange public key
        /// </summary>
        private IAsymmetricPublicKey? _CounterKeyExchangeKey = null;
        /// <summary>
        /// Signed data
        /// </summary>
        private byte[]? SignedData = null;

        /// <summary>
        /// Constructor
        /// </summary>
        public PublicKeySuite() : base(VERSION) { }

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

        /// <summary>
        /// Public key suite signature
        /// </summary>
        public SignatureContainer? Signature { get; set; }

        /// <summary>
        /// Create the signed data
        /// </summary>
        /// <returns>Signed data</returns>
        public byte[] CreateSignedData()
        {
            try
            {
                EnsureUndisposed();
                if (SignedData != null) return SignedData;
                this.ValidateObject();
                using MemoryStream ms = new();
                ms.WriteSerializerVersion()
                    .WriteNumber(VERSION)
                    .WriteAnyNullable(_KeyExchangeKey)
                    .WriteAnyNullable(_CounterKeyExchangeKey)
                    .WriteAnyNullable(SignatureKey)
                    .WriteAnyNullable(CounterSignatureKey)
                    .WriteSerializedNullable(SignedPublicKey);
                SignedData = ms.ToArray();
                return SignedData;
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch(Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }

        /// <summary>
        /// Create crypto options
        /// </summary>
        /// <returns>Options</returns>
        public CryptoOptions CreateOptions()
        {
            EnsureUndisposed();
            CryptoOptions res = new();
            res.ApplyPublicKeySuite(this);
            return res;
        }

        /// <summary>
        /// Clone this public key suite
        /// </summary>
        /// <returns>Clone</returns>
        public PublicKeySuite Clone() => IfUndisposed(() => new PublicKeySuite()
        {
            SignedData = (byte[]?)SignedData?.Clone(),
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
        protected override void Serialize(Stream stream)
        {
            CreateSignedData();
            stream.WriteBytes(SignedData!)
                .WriteSerializedNullable(Signature);
        }

        /// <inheritdoc/>
        protected override async Task SerializeAsync(Stream stream, CancellationToken cancellationToken)
        {
            CreateSignedData();
            await stream.WriteBytesAsync(SignedData!, cancellationToken).DynamicContext();
            await stream.WriteSerializedNullableAsync(Signature, cancellationToken).DynamicContext();
        }

        /// <inheritdoc/>
        protected override void Deserialize(Stream stream, int version)
        {
            SignedData = stream.ReadBytes(version, minLen: 1, maxLen: 524280).Value;
            DeserializeSignedData();
            Signature = stream.ReadSerializedNullable<SignatureContainer>(version);
        }

        /// <inheritdoc/>
        protected override async Task DeserializeAsync(Stream stream, int version, CancellationToken cancellationToken)
        {
            SignedData = (await stream.ReadBytesAsync(version, minLen: 1, maxLen: 524280, cancellationToken: cancellationToken).DynamicContext()).Value;
            DeserializeSignedData();
            Signature = await stream.ReadSerializedNullableAsync<SignatureContainer>(version, cancellationToken).DynamicContext();
        }

        /// <summary>
        /// Deserialize signed data
        /// </summary>
        private void DeserializeSignedData()
        {
            EnsureUndisposed();
            if (SignedData == null) throw new InvalidOperationException();
            using MemoryStream ms = new();
            int ssv = ms.ReadSerializerVersion(),
                ov = ms.ReadNumber<int>(ssv);
            if (ov < 1 || ov > VERSION) throw new SerializerException($"Invalid object version {ov}", new InvalidDataException());
            _KeyExchangeKey = (IAsymmetricPublicKey?)ms.ReadAnyNullable(ssv);
            _CounterKeyExchangeKey = (IAsymmetricPublicKey?)ms.ReadAnyNullable(ssv);
            SignatureKey = (ISignaturePublicKey?)ms.ReadAnyNullable(ssv);
            CounterSignatureKey = (ISignaturePublicKey?)ms.ReadAnyNullable(ssv);
            SignedPublicKey = ms.ReadSerializedNullable<AsymmetricSignedPublicKey>(ssv);
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
