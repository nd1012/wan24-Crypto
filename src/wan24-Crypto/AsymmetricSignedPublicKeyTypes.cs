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
        Unknown = 0,
        /// <summary>
        /// Root signature key
        /// </summary>
        Root = 1,
        /// <summary>
        /// Intermediate signature key
        /// </summary>
        Intermediate = 2,
        /// <summary>
        /// End key
        /// </summary>
        End = 3,
        /// <summary>
        /// Key was revoked
        /// </summary>
        Revoked = 128,
        /// <summary>
        /// All flags
        /// </summary>
#pragma warning disable CA1069 // Double constant value
        FLAGS = 128
#pragma warning restore CA1069 // Double constant value
    }
}
