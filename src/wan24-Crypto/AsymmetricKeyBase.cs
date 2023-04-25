using wan24.Core;
using wan24.ObjectValidation;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto
{
    /// <summary>
    /// Base class for an asymmetric key
    /// </summary>
    public abstract class AsymmetricKeyBase : DisposableBase, IAsymmetricKey
    {
        /// <summary>
        /// Object version
        /// </summary>
        public const int VERSION = 1;

        /// <summary>
        /// Serialized object version
        /// </summary>
        protected int? _SerializedObjectVersion = null;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="algorithm">Algorithm name</param>
        protected AsymmetricKeyBase(string algorithm) : base() => Algorithm = AsymmetricHelper.GetAlgorithm(algorithm);

        /// <inheritdoc/>
        public abstract byte[] ID { get; }

        /// <inheritdoc/>
        public IAsymmetricAlgorithm Algorithm { get; }

        /// <inheritdoc/>
        public abstract int Bits { get; }

        /// <inheritdoc/>
        [NoValidation]
        public SecureByteArray KeyData { get; protected set; } = null!;

        /// <inheritdoc/>
        int? IStreamSerializerVersion.ObjectVersion => VERSION;

        /// <inheritdoc/>
        int? IStreamSerializerVersion.SerializedObjectVersion => _SerializedObjectVersion;

        /// <summary>
        /// Serialize
        /// </summary>
        /// <param name="stream">Stream</param>
        protected virtual void Serialize(Stream stream)
        {
            stream.WriteNumber(VERSION)
                .WriteNumber(Algorithm.Value)
                .WriteBytes(KeyData.Array);
        }

        /// <summary>
        /// Serialize
        /// </summary>
        /// <param name="stream">Stream</param>
        /// <param name="cancellationToken">Cancellation token</param>
        protected virtual async Task SerializeAsync(Stream stream, CancellationToken cancellationToken)
        {
            await stream.WriteNumberAsync(VERSION, cancellationToken).DynamicContext();
            await stream.WriteNumberAsync(Algorithm.Value, cancellationToken).DynamicContext();
            await stream.WriteBytesAsync(KeyData.Array, cancellationToken).DynamicContext();
        }

        /// <summary>
        /// Deserialize
        /// </summary>
        /// <param name="stream">Stream</param>
        /// <param name="version">Serializer version</param>
        protected virtual void Deserialize(Stream stream, int version)
        {
            _SerializedObjectVersion = StreamSerializerAdapter.ReadSerializedObjectVersion(stream, version, VERSION);
            if (stream.ReadNumber<int>() != Algorithm.Value) throw new SerializerException("Asymmetric algorithm mismatch");
            KeyData?.Dispose();
            KeyData = new(stream.ReadBytes(version, minLen: 1, maxLen: ushort.MaxValue).Value);
        }

        /// <summary>
        /// Deserialize
        /// </summary>
        /// <param name="stream">Stream</param>
        /// <param name="version">Serializer version</param>
        /// <param name="cancellationToken">Cancellation token</param>
        protected virtual async Task DeserializeAsync(Stream stream, int version, CancellationToken cancellationToken)
        {
            _SerializedObjectVersion = await StreamSerializerAdapter.ReadSerializedObjectVersionAsync(stream, version, VERSION, cancellationToken).DynamicContext();
            if (await stream.ReadNumberAsync<int>(version, cancellationToken: cancellationToken).DynamicContext() != Algorithm.Value)
                throw new SerializerException("Asymmetric algorithm mismatch");
            KeyData?.Dispose();
            KeyData = new((await stream.ReadBytesAsync(version, minLen: 1, maxLen: ushort.MaxValue, cancellationToken: cancellationToken).DynamicContext()).Value);
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing) => KeyData.Dispose();

        /// <inheritdoc/>
        void IStreamSerializer.Serialize(Stream stream) => Serialize(stream);

        /// <inheritdoc/>
        Task IStreamSerializer.SerializeAsync(Stream stream, CancellationToken cancellationToken) => SerializeAsync(stream, cancellationToken);

        /// <inheritdoc/>
        void IStreamSerializer.Deserialize(Stream stream, int version) => Deserialize(stream, version);

        /// <inheritdoc/>
        Task IStreamSerializer.DeserializeAsync(Stream stream, int version, CancellationToken cancellationToken) => DeserializeAsync(stream, version, cancellationToken);
    }
}
