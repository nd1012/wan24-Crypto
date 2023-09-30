using wan24.Core;
using wan24.ObjectValidation;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto
{
    /// <summary>
    /// PAKE authentication information (needs to be sent to the server, wrapped using a PFS protocol!)
    /// </summary>
    public sealed class PakeAuth : DisposableStreamSerializerBase, IPakeRequest
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
            Payload = payload ?? Array.Empty<byte>();
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
            if (stream.Read(Key) != Key.Length) throw new IOException($"Failed to read {Identifier.Length} key bytes");
            Signature = new byte[Identifier.Length];
            if (stream.Read(Signature) != Signature.Length) throw new IOException($"Failed to read {Identifier.Length} signature bytes");
            Random = new byte[Identifier.Length];
            if (stream.Read(Random) != Random.Length) throw new IOException($"Failed to read {Identifier.Length} random bytes");
            Payload = stream.ReadBytes(version, minLen: 0, maxLen: ushort.MaxValue).Value;
        }

        /// <inheritdoc/>
        protected override async Task DeserializeAsync(Stream stream, int version, CancellationToken cancellationToken)
        {
            Identifier = (await stream.ReadBytesAsync(version, minLen: 1, maxLen: byte.MaxValue, cancellationToken: cancellationToken).DynamicContext()).Value;
            Key = new byte[Identifier.Length];
            if (await stream.ReadAsync(Key, cancellationToken).DynamicContext() != Key.Length) throw new IOException($"Failed to read {Identifier.Length} key bytes");
            Signature = new byte[Identifier.Length];
            if (await stream.ReadAsync(Signature, cancellationToken).DynamicContext() != Signature.Length) throw new IOException($"Failed to read {Identifier.Length} signature bytes");
            Random = new byte[Identifier.Length];
            if (await stream.ReadAsync(Random, cancellationToken).DynamicContext() != Random.Length) throw new IOException($"Failed to read {Identifier.Length} random bytes");
            Payload = (await stream.ReadBytesAsync(version, minLen: 0, maxLen: ushort.MaxValue, cancellationToken: cancellationToken).DynamicContext()).Value;
        }

        /// <summary>
        /// Cast as serialized data
        /// </summary>
        /// <param name="signup"><see cref="PakeAuth"/></param>
        public static implicit operator byte[](in PakeAuth signup) => signup.ToBytes();

        /// <summary>
        /// Cast from serialized data
        /// </summary>
        /// <param name="data">Serialized data</param>
        public static explicit operator PakeAuth(in byte[] data) => data.ToObject<PakeAuth>();
    }
}
