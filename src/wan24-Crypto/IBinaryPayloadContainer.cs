using wan24.StreamSerializerExtensions;

namespace wan24.Crypto
{
    /// <summary>
    /// Interface for a binary payload container
    /// </summary>
    public interface IBinaryPayloadContainer : IStreamSerializerVersion
    {
        /// <summary>
        /// Minimum payload length in bytes
        /// </summary>
        int MinPayloadLength { get; }
        /// <summary>
        /// Maximum payload length in bytes
        /// </summary>
        int MaxPayloadLength { get; }
        /// <summary>
        /// Payload
        /// </summary>
        byte[] Payload { get; }
    }
}
