using wan24.Core;
using wan24.ObjectValidation;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto
{
    /// <summary>
    /// Asymmetric public key signing request
    /// </summary>
    public sealed class AsymmetricPublicKeySigningRequest : DisposableBase, IStreamSerializerVersion
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
        /// Constructor
        /// </summary>
        public AsymmetricPublicKeySigningRequest() : base() { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="publicKey">Public key (will be copied)</param>
        public AsymmetricPublicKeySigningRequest(IAsymmetricPublicKey publicKey) : this() => PublicKey = publicKey.GetCopy();

        /// <summary>
        /// Public key (will be disposed)
        /// </summary>
        public IAsymmetricPublicKey PublicKey { get; set; } = null!;

        /// <summary>
        /// Attributes
        /// </summary>
        [CountLimit(byte.MaxValue)]
        [ItemStringLength(byte.MaxValue, ItemValidationTargets.Key)]
        [ItemStringLength(byte.MaxValue)]
        public Dictionary<string, string> Attributes { get; private set; } = new();

        /// <inheritdoc/>
        int? IStreamSerializerVersion.ObjectVersion => VERSION;

        /// <inheritdoc/>
        int? IStreamSerializerVersion.SerializedObjectVersion => _SerializedObjectVersion;

        /// <summary>
        /// Get as unsigned key
        /// </summary>
        /// <returns>Unsigned key</returns>
        public AsymmetricSignedPublicKey GetAsUnsignedKey()
        {
            EnsureUndisposed();
            this.ValidateObject();
            AsymmetricSignedPublicKey res = new()
            {
                PublicKey = PublicKey
            };
            res.Attributes.AddRange(Attributes);
            return res;
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing) => PublicKey.Dispose();

        /// <inheritdoc/>
        void IStreamSerializer.Serialize(Stream stream)
        {
            EnsureUndisposed();
            stream.WriteNumber(StreamSerializer.VERSION)
                .WriteAny(PublicKey)
                .WriteDict(Attributes);
        }

        /// <inheritdoc/>
        async Task IStreamSerializer.SerializeAsync(Stream stream, CancellationToken cancellationToken)
        {
            EnsureUndisposed();
            await stream.WriteNumberAsync(StreamSerializer.VERSION, cancellationToken).DynamicContext();
            await stream.WriteAnyAsync(PublicKey, cancellationToken).DynamicContext();
            await stream.WriteDictAsync(Attributes, cancellationToken).DynamicContext();
        }

        /// <inheritdoc/>
        void IStreamSerializer.Deserialize(Stream stream, int version)
        {
            EnsureUndisposed();
            _SerializedObjectVersion = StreamSerializerAdapter.ReadSerializedObjectVersion(stream, version, VERSION);
            PublicKey = stream.ReadAny(version) as IAsymmetricPublicKey ?? throw new SerializerException("Failed to deserialize the public key");
            Attributes = stream.ReadDict<string, string>(version, maxLen: byte.MaxValue);
        }

        /// <inheritdoc/>
        async Task IStreamSerializer.DeserializeAsync(Stream stream, int version, CancellationToken cancellationToken)
        {
            EnsureUndisposed();
            _SerializedObjectVersion = await StreamSerializerAdapter.ReadSerializedObjectVersionAsync(stream, version, VERSION, cancellationToken).DynamicContext();
            PublicKey = await stream.ReadAnyAsync(version, cancellationToken).DynamicContext() as IAsymmetricPublicKey ?? throw new SerializerException("Failed to deserialize the public key");
            Attributes = await stream.ReadDictAsync<string, string>(version, maxLen: byte.MaxValue, cancellationToken: cancellationToken).DynamicContext();
        }

        /// <summary>
        /// Cast as unsigned public key
        /// </summary>
        /// <param name="signingRequest">Signing request</param>
        public static implicit operator AsymmetricSignedPublicKey(AsymmetricPublicKeySigningRequest signingRequest) => signingRequest.GetAsUnsignedKey();

        /// <summary>
        /// Cast as serialized data
        /// </summary>
        /// <param name="request">Request</param>
        public static implicit operator byte[](AsymmetricPublicKeySigningRequest request) => request.ToBytes();

        /// <summary>
        /// Cast from serialized data
        /// </summary>
        /// <param name="data">Data</param>
        public static explicit operator AsymmetricPublicKeySigningRequest(byte[] data) => data.ToObject<AsymmetricPublicKeySigningRequest>();
    }
}
