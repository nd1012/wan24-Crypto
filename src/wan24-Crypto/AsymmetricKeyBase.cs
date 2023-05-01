using wan24.Core;
using wan24.ObjectValidation;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto
{
    /// <summary>
    /// Base class for an asymmetric key
    /// </summary>
    public abstract class AsymmetricKeyBase : DisposableStreamSerializerBase, IAsymmetricKey
    {
        /// <summary>
        /// Object version
        /// </summary>
        public const int VERSION = 1;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="algorithm">Algorithm name</param>
        protected AsymmetricKeyBase(string algorithm) : base(VERSION) => Algorithm = AsymmetricHelper.GetAlgorithm(algorithm);

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
        public abstract object Clone();

        /// <summary>
        /// Serialize
        /// </summary>
        /// <param name="stream">Stream</param>
        protected override void Serialize(Stream stream)
        {
            EnsureUndisposed();
            stream.WriteNumber(Algorithm.Value)
                .WriteBytes(KeyData.Array);
        }

        /// <summary>
        /// Serialize
        /// </summary>
        /// <param name="stream">Stream</param>
        /// <param name="cancellationToken">Cancellation token</param>
        protected override async Task SerializeAsync(Stream stream, CancellationToken cancellationToken)
        {
            EnsureUndisposed();
            await stream.WriteNumberAsync(Algorithm.Value, cancellationToken).DynamicContext();
            await stream.WriteBytesAsync(KeyData.Array, cancellationToken).DynamicContext();
        }

        /// <summary>
        /// Deserialize
        /// </summary>
        /// <param name="stream">Stream</param>
        /// <param name="version">Serializer version</param>
        protected override void Deserialize(Stream stream, int version)
        {
            EnsureUndisposed();
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
        protected override async Task DeserializeAsync(Stream stream, int version, CancellationToken cancellationToken)
        {
            EnsureUndisposed();
            if (await stream.ReadNumberAsync<int>(version, cancellationToken: cancellationToken).DynamicContext() != Algorithm.Value)
                throw new SerializerException("Asymmetric algorithm mismatch");
            KeyData?.Dispose();
            KeyData = new((await stream.ReadBytesAsync(version, minLen: 1, maxLen: ushort.MaxValue, cancellationToken: cancellationToken).DynamicContext()).Value);
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing) => KeyData.Dispose();
    }
}
