using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// <see cref="AsymmetricSignedPublicKey"/> types enumeration
    /// </summary>
    [Flags]
    public enum AsymmetricSignedPublicKeyTypes : byte
    {
        /// <summary>
        /// Unknown key (not known in PKI)
        /// </summary>
        [DisplayText("Unknown key (not known in PKI)")]
        Unknown = 0,
        /// <summary>
        /// Root signature key
        /// </summary>
        [DisplayText("Root signature key")]
        Root = 1,
        /// <summary>
        /// Intermediate signature key
        /// </summary>
        [DisplayText("Intermediate signature key")]
        Intermediate = 2,
        /// <summary>
        /// End key
        /// </summary>
        [DisplayText("End key")]
        End = 3,
        /// <summary>
        /// Key was revoked
        /// </summary>
        [DisplayText("Key was revoked")]
        Revoked = 128,
        /// <summary>
        /// All flags
        /// </summary>
#pragma warning disable CA1069 // Double constant value
        [DisplayText("All flags")]
        FLAGS = 128
#pragma warning restore CA1069 // Double constant value
    }
}
