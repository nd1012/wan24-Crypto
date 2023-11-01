using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Interface for a secure value
    /// </summary>
    public interface ISecureValue : IDisposableObject
    {
        /// <summary>
        /// Value (should/will be cleared!)
        /// </summary>
        byte[] Value { get; set; }
    }
}
