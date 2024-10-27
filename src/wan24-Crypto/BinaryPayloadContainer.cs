using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto
{
    /// <summary>
    /// Binary payload container (you should extend this type and define the min./max. payload length in bytes in the <see cref="MinPayloadLength"/> and <see cref="MaxPayloadLength"/> 
    /// properties (can be done by calling the protected constructors); default max. length is <see cref="ushort.MaxValue"/>, while the default min. length is <c>1</c> byte)
    /// </summary>
    public record class BinaryPayloadContainer : StreamSerializerRecordBase, IBinaryPayloadContainer
    {
        /// <summary>
        /// Object version
        /// </summary>
        public const int VERSION = 1;

        /// <summary>
        /// Higher level object version (<see langword="null"/>, if no higher level object version was given)
        /// </summary>
        protected readonly int? HlObjectVersion;
        /// <summary>
        /// Deserialized higher level object version (<see langword="null"/>, if no higher level object version was given or this instance wasn't deserialized)
        /// </summary>
        protected int? DeserializedHlObjectVersion = null;

        /// <summary>
        /// Constructor
        /// </summary>
        public BinaryPayloadContainer() : this(1, ushort.MaxValue) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="payload">Payload</param>
        public BinaryPayloadContainer(byte[] payload) : this(1, ushort.MaxValue, payload) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="minLen">Minimum payload length in bytes</param>
        /// <param name="maxLen">Maximum payload length in bytes</param>
        /// <param name="hlVersion">Higher level object version</param>
        protected BinaryPayloadContainer(int minLen, int maxLen, int? hlVersion = null) : base(VERSION)
        {
            if (hlVersion is not null && hlVersion < 1) throw new ArgumentOutOfRangeException(nameof(hlVersion));
            HlObjectVersion = hlVersion;
            ArgumentOutOfRangeException.ThrowIfNegative(minLen);
            ArgumentOutOfRangeException.ThrowIfLessThan(maxLen, minLen);
            (MinPayloadLength, MaxPayloadLength) = (minLen, maxLen);
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="minLen">Minimum payload length in bytes</param>
        /// <param name="maxLen">Maximum payload length in bytes</param>
        /// <param name="payload">Payload</param>
        /// <param name="hlVersion">Higher level object version</param>
        protected BinaryPayloadContainer(int minLen, int maxLen, byte[] payload, int? hlVersion = null) : this(minLen, maxLen, hlVersion)
        {
            if (payload.Length < MinPayloadLength || payload.Length > MaxPayloadLength)
                throw new ArgumentException($"Invalid payload length ({MinPayloadLength}-{MaxPayloadLength} bytes allowed, {payload.Length} bytes given)", nameof(payload));
            Payload = payload;
        }

        /// <inheritdoc/>
        public virtual int MinPayloadLength { get; protected set; }

        /// <inheritdoc/>
        public virtual int MaxPayloadLength { get; protected set; }

        /// <inheritdoc/>
        public virtual byte[] Payload { get; protected set; } = null!;

        /// <inheritdoc/>
        protected override void Serialize(Stream stream)
        {
            if (Payload is null) throw new SerializerException("Missing payload", new InvalidOperationException());
            stream.WriteNumberNullable(HlObjectVersion);
            stream.WriteBytes(Payload);
        }

        /// <inheritdoc/>
        protected override async Task SerializeAsync(Stream stream, CancellationToken cancellationToken)
        {
            if (Payload is null) throw new SerializerException("Missing payload", new InvalidOperationException());
            await stream.WriteNumberNullableAsync(HlObjectVersion, cancellationToken).DynamicContext();
            await stream.WriteBytesAsync(Payload, cancellationToken).DynamicContext();
        }

        /// <inheritdoc/>
        protected override void Deserialize(Stream stream, int version)
        {
            DeserializeHlVersion(stream, version);
            Payload = stream.ReadArray<byte>(version, minLen: MinPayloadLength, maxLen: MaxPayloadLength);
        }

        /// <inheritdoc/>
        protected override async Task DeserializeAsync(Stream stream, int version, CancellationToken cancellationToken)
        {
            await DeserializeHlVersionAsync(stream, version, cancellationToken).DynamicContext();
            Payload = await stream.ReadArrayAsync<byte>(version, minLen: MinPayloadLength, maxLen: MaxPayloadLength, cancellationToken: cancellationToken).DynamicContext();
        }

        /// <summary>
        /// Deserialize the higher level object version
        /// </summary>
        /// <param name="stream">Stream</param>
        /// <param name="version">Serializer version</param>
        protected virtual void DeserializeHlVersion(Stream stream, int version)
        {
            DeserializedHlObjectVersion = stream.ReadNumberNullable<int>(version);
            EnsureValidHlVersion();
        }

        /// <summary>
        /// Deserialize the higher level object version
        /// </summary>
        /// <param name="stream">Stream</param>
        /// <param name="version">Serializer version</param>
        /// <param name="cancellationToken">Cancellation token</param>
        protected virtual async Task DeserializeHlVersionAsync(Stream stream, int version, CancellationToken cancellationToken)
        {
            DeserializedHlObjectVersion = await stream.ReadNumberNullableAsync<int>(version, cancellationToken: cancellationToken).DynamicContext();
            EnsureValidHlVersion();
        }

        /// <summary>
        /// Ensure a valid deserialized higher level object version
        /// </summary>
        protected virtual void EnsureValidHlVersion()
        {
            if (DeserializedHlObjectVersion is null)
            {
                if (HlObjectVersion is not null) throw new SerializerException("No deserialized higher level object version, but higher level object version defined", new InvalidDataException());
            }
            else if (HlObjectVersion is null)
            {
                throw new SerializerException("Deserialized higher level object version, but no higher level object version defined", new InvalidDataException());
            }
            else if (DeserializedHlObjectVersion > HlObjectVersion)
            {
                throw new SerializerException($"Deserialized higher level object version invalid ({DeserializedHlObjectVersion}/{HlObjectVersion})", new InvalidDataException());
            }
        }
    }
}
