using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto
{
    /// <summary>
    /// Key exchange data container
    /// </summary>
    public sealed class KeyExchangeDataContainer : StreamSerializerBase, ICloneable
    {
        /// <summary>
        /// Object version
        /// </summary>
        public const int VERSION = 1;

        /// <summary>
        /// Constructor
        /// </summary>
        public KeyExchangeDataContainer() : base(VERSION) { }

        /// <summary>
        /// Key exchange data
        /// </summary>
        public byte[] KeyExchangeData { get; set; } = null!;

        /// <summary>
        /// Counter key exchange data
        /// </summary>
        public byte[]? CounterKeyExchangeData { get; set; }

        /// <summary>
        /// Clone this instance
        /// </summary>
        /// <returns>Clone</returns>
        public KeyExchangeDataContainer Clone() => new()
        {
            KeyExchangeData = (byte[])KeyExchangeData.Clone(),
            CounterKeyExchangeData = (byte[]?)CounterKeyExchangeData?.Clone()
        };

        /// <inheritdoc/>
        protected override void Serialize(Stream stream)
        {
            stream.WriteBytes(KeyExchangeData)
                .WriteBytesNullable(CounterKeyExchangeData);
        }

        /// <inheritdoc/>
        protected override async Task SerializeAsync(Stream stream, CancellationToken cancellationToken)
        {
            await stream.WriteBytesAsync(KeyExchangeData, cancellationToken).DynamicContext();
            await stream.WriteBytesNullableAsync(CounterKeyExchangeData, cancellationToken).DynamicContext();
        }

        /// <inheritdoc/>
        protected override void Deserialize(Stream stream, int version)
        {
            KeyExchangeData = stream.ReadBytes(version, minLen: 1, maxLen: ushort.MaxValue).Value;
            CounterKeyExchangeData = stream.ReadBytesNullable(version, minLen: 1, maxLen: ushort.MaxValue)?.Value;
        }

        /// <inheritdoc/>
        protected override async Task DeserializeAsync(Stream stream, int version, CancellationToken cancellationToken)
        {
            KeyExchangeData = (await stream.ReadBytesAsync(version, minLen: 1, maxLen: ushort.MaxValue, cancellationToken: cancellationToken).DynamicContext()).Value;
            CounterKeyExchangeData = (await stream.ReadBytesNullableAsync(version, minLen: 1, maxLen: ushort.MaxValue, cancellationToken: cancellationToken).DynamicContext())?.Value;
        }

        /// <inheritdoc/>
        object ICloneable.Clone() => Clone();

        /// <summary>
        /// Cast as serialized data
        /// </summary>
        /// <param name="keyExchangeData">Key exchange data</param>
        public static implicit operator byte[](KeyExchangeDataContainer keyExchangeData) => keyExchangeData.ToBytes();

        /// <summary>
        /// Cast from serialized data
        /// </summary>
        /// <param name="data">Data</param>
        public static explicit operator KeyExchangeDataContainer(byte[] data) => data.ToObject<KeyExchangeDataContainer>();
    }
}
