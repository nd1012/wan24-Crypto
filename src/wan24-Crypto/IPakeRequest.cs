using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Interface for a PAKE request (all values will be cleared!)
    /// </summary>
    public interface IPakeRequest : IDisposableObject
    {
        /// <summary>
        /// Identifier
        /// </summary>
        byte[] Identifier { get; }
        /// <summary>
        /// Key (XORed with the signature key, when authenticating)
        /// </summary>
        byte[] Key { get; }
        /// <summary>
        /// Signature
        /// </summary>
        byte[] Signature { get; }
        /// <summary>
        /// Payload
        /// </summary>
        byte[] Payload { get; }
        /// <summary>
        /// Random bytes
        /// </summary>
        byte[] Random { get; }
    }
}
