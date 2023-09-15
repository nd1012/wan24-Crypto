using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto
{
    /// <summary>
    /// PAKE record (keep the contents secret!)
    /// </summary>
    public sealed class PakeRecord : StreamSerializerBase, IPakeRecord
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
        public PakeRecord(in byte[] identifier, in byte[] secret, in byte[] key) : this()
        {
            Identifier = identifier;
            Secret = secret;
            SignatureKey = key;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="existing">Existing PAKE record (values will be copied)</param>
        public PakeRecord(in IPakeRecord existing) : this()
        {
            Identifier = existing.Identifier.CloneArray();
            Secret = existing.Secret.CloneArray();
            SignatureKey = existing.SignatureKey.CloneArray();
        }

        /// <summary>
        /// Constructor
        /// </summary>
        public PakeRecord() : base(VERSION) { }

        /// <inheritdoc/>
        public byte[] Identifier { get; private set; } = null!;

        /// <inheritdoc/>
        public byte[] Secret { get; private set; } = null!;

        /// <inheritdoc/>
        public byte[] SignatureKey { get; private set; } = null!;

        /// <summary>
        /// Clear the contents
        /// </summary>
        public void Clear()
        {
            Identifier?.Clear();
            Secret?.Clear();
            SignatureKey?.Clear();
        }

        /// <inheritdoc/>
        protected override void Serialize(Stream stream)
            => stream.WriteBytes(Identifier)
                .WriteBytes(Secret)
                .WriteBytes(SignatureKey);

        /// <inheritdoc/>
        protected override async Task SerializeAsync(Stream stream, CancellationToken cancellationToken)
        {
            await stream.WriteBytesAsync(Identifier, cancellationToken).DynamicContext();
            await stream.WriteBytesAsync(Secret, cancellationToken).DynamicContext();
            await stream.WriteBytesAsync(SignatureKey, cancellationToken).DynamicContext();
        }

        /// <inheritdoc/>
        protected override void Deserialize(Stream stream, int version)
        {
            Identifier = stream.ReadBytes(version, minLen: 1, maxLen: byte.MaxValue).Value;
            Secret = stream.ReadBytes(version, minLen: 1, maxLen: byte.MaxValue).Value;
            SignatureKey = stream.ReadBytes(version, minLen: 1, maxLen: byte.MaxValue).Value;
        }

        /// <inheritdoc/>
        protected override async Task DeserializeAsync(Stream stream, int version, CancellationToken cancellationToken)
        {
            Identifier = (await stream.ReadBytesAsync(version, minLen: 1, maxLen: byte.MaxValue, cancellationToken: cancellationToken).DynamicContext()).Value;
            Secret = (await stream.ReadBytesAsync(version, minLen: 1, maxLen: byte.MaxValue, cancellationToken: cancellationToken).DynamicContext()).Value;
            SignatureKey = (await stream.ReadBytesAsync(version, minLen: 1, maxLen: byte.MaxValue, cancellationToken: cancellationToken).DynamicContext()).Value;
        }

        /// <summary>
        /// Cast as serialized data
        /// </summary>
        /// <param name="signup"><see cref="PakeRecord"/></param>
        public static implicit operator byte[](in PakeRecord signup) => signup.ToBytes();

        /// <summary>
        /// Cast from serialized data
        /// </summary>
        /// <param name="data">Serialized data</param>
        public static explicit operator PakeRecord(in byte[] data) => data.ToObject<PakeRecord>();
    }
}
