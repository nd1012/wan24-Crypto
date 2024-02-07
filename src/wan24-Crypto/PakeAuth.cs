using wan24.Core;
using wan24.ObjectValidation;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto
{
    /// <summary>
    /// PAKE authentication information (needs to be sent to the server, wrapped using a PFS protocol!)
    /// </summary>
    public sealed record class PakeAuth : DisposableStreamSerializerRecordBase, IPakeRequest
    {
        /// <summary>
        /// Object version
        /// </summary>
        public const int VERSION = 1;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="identifier">Identifier (will be cleared!)</param>
        /// <param name="key">Key (will be cleared!)</param>
        /// <param name="signature">Signature (will be cleared!)</param>
        /// <param name="random">Random bytes (will be cleared!)</param>
        /// <param name="payload">Payload (max. <see cref="ushort.MaxValue"/> length; will be cleared!)</param>
        internal PakeAuth(in byte[] identifier, in byte[] key, in byte[] signature, in byte[] random, in byte[]? payload = null) : this()
        {
            if (payload is not null && payload.Length > ushort.MaxValue) throw new ArgumentOutOfRangeException(nameof(payload));
            Identifier = identifier;
            Key = key;
            Signature = signature;
            Random = random;
            Payload = payload ?? [];
        }

        /// <summary>
        /// Constructor
        /// </summary>
        public PakeAuth() : base(VERSION) { }

        /// <inheritdoc/>
        [CountLimit(1, byte.MaxValue)]
        public byte[] Identifier { get; private set; } = null!;

        /// <inheritdoc/>
        [CountLimit(1, byte.MaxValue)]
        [SensitiveData]
        public byte[] Key { get; private set; } = null!;

        /// <inheritdoc/>
        [CountLimit(1, byte.MaxValue)]
        public byte[] Signature { get; private set; } = null!;

        /// <inheritdoc/>
        [CountLimit(0, ushort.MaxValue)]
        [SensitiveData]
        public byte[] Payload { get; private set; } = null!;

        /// <inheritdoc/>
        [CountLimit(1, byte.MaxValue)]
        public byte[] Random { get; private set; } = null!;

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            Identifier.Clear();
            Key.Clear();
            Signature.Clear();
            Random.Clear();
            Payload.Clear();
        }

        /// <inheritdoc/>
        protected override async Task DisposeCore()
        {
            await base.DisposeCore().DynamicContext();
            Identifier.Clear();
            Key.Clear();
            Signature.Clear();
            Random.Clear();
            Payload.Clear();
        }

        /// <inheritdoc/>
        protected override void Serialize(Stream stream)
        {
            stream.WriteBytes(Identifier);
            stream.Write(Key);
            stream.Write(Signature);
            stream.Write(Random);
            stream.WriteBytes(Payload);
        }

        /// <inheritdoc/>
        protected override async Task SerializeAsync(Stream stream, CancellationToken cancellationToken)
        {
            await stream.WriteBytesAsync(Identifier, cancellationToken).DynamicContext();
            await stream.WriteAsync(Key, cancellationToken).DynamicContext();
            await stream.WriteAsync(Signature, cancellationToken).DynamicContext();
            await stream.WriteAsync(Random, cancellationToken).DynamicContext();
            await stream.WriteBytesAsync(Payload, cancellationToken).DynamicContext();
        }

        /// <inheritdoc/>
        protected override void Deserialize(Stream stream, int version)
        {
            Identifier = stream.ReadBytes(version, minLen: 1, maxLen: byte.MaxValue).Value;
            Key = new byte[Identifier.Length];
            stream.ReadExactly(Key);
            Signature = new byte[Identifier.Length];
            stream.ReadExactly(Signature);
            Random = new byte[Identifier.Length];
            stream.ReadExactly(Random);
            Payload = stream.ReadBytes(version, minLen: 0, maxLen: ushort.MaxValue).Value;
        }

        /// <inheritdoc/>
        protected override async Task DeserializeAsync(Stream stream, int version, CancellationToken cancellationToken)
        {
            Identifier = (await stream.ReadBytesAsync(version, minLen: 1, maxLen: byte.MaxValue, cancellationToken: cancellationToken).DynamicContext()).Value;
            Key = new byte[Identifier.Length];
            await stream.ReadExactlyAsync(Key, cancellationToken).DynamicContext();
            Signature = new byte[Identifier.Length];
            await stream.ReadExactlyAsync(Signature, cancellationToken).DynamicContext();
            Random = new byte[Identifier.Length];
            await stream.ReadExactlyAsync(Random, cancellationToken).DynamicContext();
            Payload = (await stream.ReadBytesAsync(version, minLen: 0, maxLen: ushort.MaxValue, cancellationToken: cancellationToken).DynamicContext()).Value;
        }

        /// <summary>
        /// Cast as serialized data
        /// </summary>
        /// <param name="auth"><see cref="PakeAuth"/></param>
        public static implicit operator byte[](in PakeAuth auth) => auth.ToBytes();

        /// <summary>
        /// Cast from serialized data
        /// </summary>
        /// <param name="data">Serialized data</param>
        public static explicit operator PakeAuth(in byte[] data) => data.ToObject<PakeAuth>();
    }
}
