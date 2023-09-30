namespace wan24.Crypto.Authentication
{
    /// <summary>
    /// Interface for a PAKE authenticaion record
    /// </summary>
    public interface IPakeAuthRecord : IPakeRecord
    {
        /// <summary>
        /// Raw secret (unprotected; this is sensitive data and should be stored encrypted; will be cleared!)
        /// </summary>
        public byte[] RawSecret { get; }
        /// <summary>
        /// Authentication key (this is sensitive data and should be stored encrypted; will be cleared!)
        /// </summary>
        public byte[] Key { get; }
    }
}
