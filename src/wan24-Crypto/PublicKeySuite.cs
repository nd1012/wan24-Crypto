using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto
{
    /// <summary>
    /// Public key suite
    /// </summary>
    public sealed record class PublicKeySuite : DisposableStreamSerializerRecordBase, ICloneable
    {
        /// <summary>
        /// Object version
        /// </summary>
        public const int VERSION = 2;

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
                if (value is not null && !value.Algorithm.CanExchangeKey) throw new ArgumentException("Key can't key exchange", nameof(value));
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
                if (value is not null && !value.Algorithm.CanExchangeKey) throw new ArgumentException("Key can't key exchange", nameof(value));
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
        /// Signed public counter key (will be disposed)
        /// </summary>
        public AsymmetricSignedPublicKey? SignedPublicCounterKey { get; set; }

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
                if (SignedData is not null) return SignedData;
                this.ValidateObject();
                using MemoryStream ms = new();
                ms.WriteSerializerVersion()
                    .WriteNumber(VERSION)
                    .WriteBytesNullable(_KeyExchangeKey?.Export())
                    .WriteBytesNullable(_CounterKeyExchangeKey?.Export())
                    .WriteBytesNullable(SignatureKey?.Export())
                    .WriteBytesNullable(CounterSignatureKey?.Export())
                    .WriteSerializedNullable(SignedPublicKey)
                    .WriteSerializedNullable(SignedPublicCounterKey);
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
        /// Get a copy of this instance
        /// </summary>
        /// <returns>Instance copy</returns>
        public PublicKeySuite GetCopy() => IfUndisposed(() => new PublicKeySuite()
        {
            SignedData = (byte[]?)SignedData?.Clone(),
            _KeyExchangeKey = _KeyExchangeKey?.GetCopy(),
            _CounterKeyExchangeKey = _CounterKeyExchangeKey?.GetCopy(),
            SignatureKey = (ISignaturePublicKey?)SignatureKey?.GetCopy(),
            CounterSignatureKey = (ISignaturePublicKey?)CounterSignatureKey?.GetCopy(),
            SignedPublicKey = SignedPublicKey?.GetCopy(),
            SignedPublicCounterKey = SignedPublicCounterKey?.GetCopy()
        });

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            _KeyExchangeKey?.Dispose();
            _CounterKeyExchangeKey?.Dispose();
            SignatureKey?.Dispose();
            CounterSignatureKey?.Dispose();
            SignedPublicKey?.Dispose();
            SignedPublicCounterKey?.Dispose();
        }

        /// <inheritdoc/>
        protected override Task DisposeCore()
        {
            _KeyExchangeKey?.Dispose();
            _CounterKeyExchangeKey?.Dispose();
            SignatureKey?.Dispose();
            CounterSignatureKey?.Dispose();
            SignedPublicKey?.Dispose();
            SignedPublicCounterKey?.Dispose();
            return Task.CompletedTask;
        }

        /// <inheritdoc/>
        object ICloneable.Clone() => GetCopy();

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
            if (SignedData is null) throw new InvalidOperationException();
            using MemoryStream ms = new(SignedData);
            int ssv = ms.ReadSerializerVersion(),
                ov = ms.ReadNumber<int>(ssv);
            if (ov < 1 || ov > VERSION) throw new SerializerException($"Invalid object version {ov}", new InvalidDataException());
            byte[]? keyData = ms.ReadBytesNullable(ssv, minLen: 1, maxLen: short.MaxValue)?.Value;
            IAsymmetricPublicKey? key = null;
            try
            {
                if (keyData is not null)
                {
                    key = AsymmetricKeyBase.Import<IAsymmetricPublicKey>(keyData);
                    if (!key.Algorithm.CanExchangeKey) throw new SerializerException("Invalid public key exchange key");
                    _KeyExchangeKey = key;
                }
                keyData = ms.ReadBytesNullable(ssv, minLen: 1, maxLen: short.MaxValue)?.Value;
                if (keyData is not null)
                {
                    key = AsymmetricKeyBase.Import<IAsymmetricPublicKey>(keyData);
                    if (!key.Algorithm.CanExchangeKey) throw new SerializerException("Invalid public counter key exchange key");
                    _CounterKeyExchangeKey = key;
                }
                keyData = ms.ReadBytesNullable(ssv, minLen: 1, maxLen: short.MaxValue)?.Value;
                if (keyData is not null) SignatureKey = AsymmetricKeyBase.Import<ISignaturePublicKey>(keyData);
                keyData = ms.ReadBytesNullable(ssv, minLen: 1, maxLen: short.MaxValue)?.Value;
                if (keyData is not null) CounterSignatureKey = AsymmetricKeyBase.Import<ISignaturePublicKey>(keyData);
            }
            catch
            {
                key?.Dispose();
                keyData?.Clear();
                throw;
            }
            SignedPublicKey = ms.ReadSerializedNullable<AsymmetricSignedPublicKey>(ssv);
            switch (ov)// Object version switch
            {
                case 2:
                    SignedPublicCounterKey = ms.ReadSerializedNullable<AsymmetricSignedPublicKey>(ssv);
                    break;
            }
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
