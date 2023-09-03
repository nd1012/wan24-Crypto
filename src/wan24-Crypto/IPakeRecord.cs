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
        /// Secret (will be cleared!)
        /// </summary>
        byte[] Secret { get; }
        /// <summary>
        /// Signature key (will be cleared!)
        /// </summary>
        byte[] SignatureKey { get; }
    }
}
