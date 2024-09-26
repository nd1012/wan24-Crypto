using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto
{
    /// <summary>
    /// Key exchange data container
    /// </summary>
    public sealed record class KeyExchangeDataContainer : StreamSerializerRecordBase, ICloneable
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
        /// Max. key exchange data length in bytes
        /// </summary>
        public static int MaxKeyExchangeDataLength { get; set; } = ushort.MaxValue;

        /// <summary>
        /// Key exchange data
        /// </summary>
        [RuntimeCountLimit("wan24.Crypto.KeyExchangeDataContainer.MaxKeyExchangeDataLength", min: 1)]
        public byte[] KeyExchangeData { get; set; } = null!;

        /// <summary>
        /// Counter key exchange data
        /// </summary>
        [RuntimeCountLimit("wan24.Crypto.KeyExchangeDataContainer.MaxKeyExchangeDataLength", min: 1)]
        public byte[]? CounterKeyExchangeData { get; set; }

        /// <summary>
        /// Get a copy of this instance
        /// </summary>
        /// <returns>Instance copy</returns>
        public KeyExchangeDataContainer GetCopy() => new()
        {
            KeyExchangeData = KeyExchangeData.CloneArray(),
            CounterKeyExchangeData = CounterKeyExchangeData?.CloneArray()
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
            KeyExchangeData = stream.ReadArray<byte>(version, minLen: 1, maxLen: ushort.MaxValue);
            CounterKeyExchangeData = stream.ReadArrayNullable<byte>(version, minLen: 1, maxLen: ushort.MaxValue);
        }

        /// <inheritdoc/>
        protected override async Task DeserializeAsync(Stream stream, int version, CancellationToken cancellationToken)
        {
            KeyExchangeData = await stream.ReadArrayAsync<byte>(version, minLen: 1, maxLen: ushort.MaxValue, cancellationToken: cancellationToken).DynamicContext();
            CounterKeyExchangeData = await stream.ReadArrayNullableAsync<byte>(version, minLen: 1, maxLen: ushort.MaxValue, cancellationToken: cancellationToken).DynamicContext();
        }

        /// <inheritdoc/>
        object ICloneable.Clone() => GetCopy();

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
