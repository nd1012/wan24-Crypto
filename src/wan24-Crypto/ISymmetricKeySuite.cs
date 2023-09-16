using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Interface for a symmetric key suite
    /// </summary>
    public interface ISymmetricKeySuite : IDisposableObject
    {
        /// <summary>
        /// Identifier (public; used for identification during authentication; will be cleared!)
        /// </summary>
        byte[]? Identifier { get; }
        /// <summary>
        /// Expanded symmetric key (private!; used for en-/decryption and authentication; will be disposed!)
        /// </summary>
        SecureByteArray ExpandedKey { get; }
    }
}
