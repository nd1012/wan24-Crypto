namespace wan24.Crypto
{
    /// <summary>
    /// Interface for a PAKE record
    /// </summary>
    public interface IPakeRecord
    {
        /// <summary>
        /// Identifier (will be cleared!)
        /// </summary>
        byte[] Identifier { get; }
        /// <summary>
        /// Secret (protected with the authentication key; this is sensitive data and should be stored encrypted; will be cleared!)
        /// </summary>
        byte[] Secret { get; }
        /// <summary>
        /// Signature key (this is sensitive data and should be stored encrypted; will be cleared!)
        /// </summary>
        byte[] SignatureKey { get; }
    }
}
