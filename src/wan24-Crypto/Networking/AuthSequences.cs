namespace wan24.Crypto.Networking
{
    /// <summary>
    /// Authentication sequences enumeration
    /// </summary>
    public enum AuthSequences : byte
    {
        /// <summary>
        /// Signup (client does send a signup request)
        /// </summary>
        Signup = 0,
        /// <summary>
        /// Authentication (client does send an authentication request)
        /// </summary>
        Authentication = 1,
        /// <summary>
        /// Public server key request (peer will send a public key suite)
        /// </summary>
        PublicKeyRequest = 2,
        /// <summary>
        /// Error response (peer closed the connection)
        /// </summary>
        Error = byte.MaxValue
    }
}
