using wan24.Core;
using wan24.ObjectValidation;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto
{
    /// <summary>
    /// PAKE signup information (needs to be sent to the server, wrapped using a PFS protocol!)
    /// </summary>
    public sealed record class PakeSignup : DisposableStreamSerializerRecordBase, IPakeRequest
    {
        /// <summary>
        /// Object version
        /// </summary>
        public const int VERSION = 1;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="identifier">Identifier (will be cleared!)</param>
        /// <param name="secret">Secret (will be cleared!)</param>
        /// <param name="key">Key (will be cleared!)</param>
        /// <param name="signature">Signature (will be cleared!)</param>
        /// <param name="random">Random bytes (will be cleared!)</param>
        /// <param name="payload">Payload (max. <see cref="ushort.MaxValue"/> length; will be cleared!)</param>
        internal PakeSignup(in byte[] identifier, in byte[] secret, in byte[] key, in byte[] signature, in byte[] random, in byte[]? payload = null) : this()
        {
            if (payload is not null && payload.Length > ushort.MaxValue) throw new ArgumentOutOfRangeException(nameof(payload));
            Identifier = identifier;
            Secret = secret;
            Key = key;
            Signature = signature;
            Random = random;
            Payload = payload ?? [];
        }

        /// <summary>
        /// Constructor
        /// </summary>
        public PakeSignup() : base(VERSION) { }

        /// <inheritdoc/>
        [CountLimit(1, byte.MaxValue)]
        public byte[] Identifier { get; internal set; } = null!;

        /// <summary>
        /// Secret (will be cleared!)
        /// </summary>
        [SensitiveData]
        [CountLimit(1, byte.MaxValue)]
        public byte[] Secret { get; internal set; } = null!;

        /// <inheritdoc/>
        [SensitiveData]
        [CountLimit(1, byte.MaxValue)]
        public byte[] Key { get; internal set; } = null!;

        /// <inheritdoc/>
        [CountLimit(1, byte.MaxValue)]
        public byte[] Random { get; internal set; } = null!;

        /// <inheritdoc/>
        [SensitiveData]
        [CountLimit(0, ushort.MaxValue)]
        public byte[] Payload { get; internal set; } = null!;

        /// <inheritdoc/>
        [CountLimit(1, byte.MaxValue)]
        public byte[] Signature { get; internal set; } = null!;

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            Identifier.Clear();
            Secret.Clear();
            Key.Clear();
            Signature.Clear();
            Payload.Clear();
            Random.Clear();
        }

        /// <inheritdoc/>
        protected override async Task DisposeCore()
        {
            await base.DisposeCore().DynamicContext();
            Identifier.Clear();
            Secret.Clear();
            Key.Clear();
            Signature.Clear();
            Payload.Clear();
            Random.Clear();
        }

        /// <inheritdoc/>
        protected override void Serialize(Stream stream)
        {
            stream.WriteBytes(Identifier)
                .Write(Secret);
            stream.Write(Key);
            stream.Write(Signature);
            stream.Write(Random);
            stream.WriteBytes(Payload);
        }

        /// <inheritdoc/>
        protected override async Task SerializeAsync(Stream stream, CancellationToken cancellationToken)
        {
            await stream.WriteBytesAsync(Identifier, cancellationToken).DynamicContext();
            await stream.WriteAsync(Secret, cancellationToken).DynamicContext();
            await stream.WriteAsync(Key, cancellationToken).DynamicContext();
            await stream.WriteAsync(Signature, cancellationToken).DynamicContext();
            await stream.WriteAsync(Random, cancellationToken).DynamicContext();
            await stream.WriteBytesAsync(Payload, cancellationToken).DynamicContext();
        }

        /// <inheritdoc/>
        protected override void Deserialize(Stream stream, int version)
        {
            Identifier = stream.ReadBytes(version, minLen: 1, maxLen: byte.MaxValue).Value;
            Secret = new byte[Identifier.Length];
            stream.ReadExactly(Secret);
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
            Secret = new byte[Identifier.Length];
            await stream.ReadExactlyAsync(Secret, cancellationToken).DynamicContext();
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
        /// <param name="signup"><see cref="PakeSignup"/></param>
        public static implicit operator byte[](in PakeSignup signup) => signup.ToBytes();

        /// <summary>
        /// Cast from serialized data
        /// </summary>
        /// <param name="data">Serialized data</param>
        public static explicit operator PakeSignup(in byte[] data) => data.ToObject<PakeSignup>();
    }
}
