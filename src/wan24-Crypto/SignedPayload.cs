using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto
{
    /// <summary>
    /// Signed payload
    /// </summary>
    /// <typeparam name="T">Payload type</typeparam>
    public record class SignedPayload<T> : StreamSerializerRecordBase where T : class, IStreamSerializer
    {
        /// <summary>
        /// Object version
        /// </summary>
        public const int VERSION = 1;

        /// <summary>
        /// Signed data
        /// </summary>
        protected byte[]? SignedData = null;
        /// <summary>
        /// Maximum length of the signed data in bytes
        /// </summary>
        protected int SignedDataMaxLength = ushort.MaxValue;

        /// <summary>
        /// Constructor
        /// </summary>
        public SignedPayload() : base(VERSION) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="payload">Payload</param>
        /// <param name="privateKey">Private key</param>
        /// <param name="options">Options</param>
        public SignedPayload(T payload, ISignaturePrivateKey privateKey, CryptoOptions? options = null) : this()
        {
            Payload = payload;
            Signature = privateKey.SignData(CreateSignedData(), options: options);
        }

        /// <summary>
        /// Payload
        /// </summary>
        public T Payload { get; protected set; } = null!;

        /// <summary>
        /// Signature
        /// </summary>
        public SignatureContainer Signature { get; protected set; } = null!;

        /// <summary>
        /// Create the signature
        /// </summary>
        /// <param name="privateKey">Private key</param>
        /// <param name="purpose">Purpose</param>
        /// <param name="options">Options</param>
        public void Sign(ISignaturePrivateKey privateKey, string? purpose = null, CryptoOptions? options = null)
            => Signature = privateKey.SignData(CreateSignedData(), purpose, options);

        /// <summary>
        /// Validate the signature
        /// </summary>
        /// <param name="throwOnError">Throw an exception on error?</param>
        /// <returns>If the signature is valid</returns>
        public bool Validate(bool throwOnError = true)
        {
            if (Signature is null) throw new InvalidOperationException();
            using ISignaturePublicKey publicKey = Signature.SignerPublicKey;
            return publicKey.ValidateSignature(Signature, CreateSignedData(), throwOnError);
        }

        /// <summary>
        /// Create signed data
        /// </summary>
        /// <returns>Signed data</returns>
        public byte[] CreateSignedData()
        {
            if (SignedData is not null) return SignedData;
            if (Payload is null) throw new InvalidOperationException("Missing payload");
            using MemoryStream ms = new();
            ms.WriteSerializerVersion()
                .WriteNumber(VERSION)
                .WriteSerialized(Payload);
            CreateSignedDataInt(ms);
            SignedData = ms.ToArray();
            return SignedData;
        }

        /// <summary>
        /// Deserialize signed data
        /// </summary>
        protected void DeserializeSignedData()
        {
            if (SignedData is null) throw new InvalidOperationException("Missing signed data");
            using MemoryStream ms = new(SignedData);
            int ssv = ms.ReadSerializerVersion(),
                ov = ms.ReadNumber<int>(ssv);
            if (ov < 1 || ov > VERSION) throw new SerializerException($"Invalid object version {ov}");
            Payload = ms.ReadSerialized<T>(ssv);
            DeserializeSignedDataInt(ms, ssv);
        }

        /// <summary>
        /// Create signed data
        /// </summary>
        /// <param name="stream">Stream</param>
        protected virtual void CreateSignedDataInt(Stream stream) { }

        /// <summary>
        /// Deserialize signed data
        /// </summary>
        /// <param name="stream">Stream</param>
        /// <param name="version">Serializer version</param>
        protected virtual void DeserializeSignedDataInt(Stream stream, int version) { }

        /// <inheritdoc/>
        protected override void Serialize(Stream stream)
        {
            if (Signature is null) throw new InvalidOperationException("Missing signature");
            stream.WriteBytes(SignedData)
                .WriteSerialized(Signature);
        }

        /// <inheritdoc/>
        protected override async Task SerializeAsync(Stream stream, CancellationToken cancellationToken)
        {
            if (Signature is null) throw new InvalidOperationException("Missing signature");
            await stream.WriteBytesAsync(SignedData, cancellationToken).DynamicContext();
            await stream.WriteSerializedAsync(Signature, cancellationToken).DynamicContext();
        }

        /// <inheritdoc/>
        protected override void Deserialize(Stream stream, int version)
        {
            SignedData = stream.ReadArray<byte>(version, minLen: 1, maxLen: SignedDataMaxLength);
            DeserializeSignedData();
            Signature = stream.ReadSerialized<SignatureContainer>(version);
        }

        /// <inheritdoc/>
        protected override async Task DeserializeAsync(Stream stream, int version, CancellationToken cancellationToken)
        {
            SignedData = await stream.ReadArrayAsync<byte>(version, minLen: 1, maxLen: SignedDataMaxLength, cancellationToken: cancellationToken).DynamicContext();
            DeserializeSignedData();
            Signature = await stream.ReadSerializedAsync<SignatureContainer>(version, cancellationToken).DynamicContext();
        }

        /// <summary>
        /// Cast as serialized data
        /// </summary>
        /// <param name="signedPayload">Signed payload</param>
        public static implicit operator byte[](SignedPayload<T> signedPayload) => signedPayload.ToBytes();

        /// <summary>
        /// Cast as payload
        /// </summary>
        /// <param name="signedPayload">Signed payload</param>
        public static implicit operator T(SignedPayload<T> signedPayload) => signedPayload.Payload;

        /// <summary>
        /// Cast as signature
        /// </summary>
        /// <param name="signedPayload">Signed payload</param>
        public static implicit operator SignatureContainer(SignedPayload<T> signedPayload) => signedPayload.Signature;
    }
}
