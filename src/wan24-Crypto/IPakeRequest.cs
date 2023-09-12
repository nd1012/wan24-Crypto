using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Interface fr a PAKE request
    /// </summary>
    public interface IPakeRequest : IDisposableObject
    {
        /// <summary>
        /// Identifier
        /// </summary>
        byte[] Identifier { get; }
        /// <summary>
        /// Key
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
