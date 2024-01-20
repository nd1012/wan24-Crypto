using wan24.Core;

namespace wan24.Crypto.Authentication
{
    /// <summary>
    /// Authentication sequences enumeration
    /// </summary>
    public enum AuthSequences : byte
    {
        /// <summary>
        /// Signup (client does send a signup request)
        /// </summary>
        [DisplayText("Signup (client does send a signup request)")]
        Signup = 0,
        /// <summary>
        /// Authentication (client does send an authentication request)
        /// </summary>
        [DisplayText("Authentication (client does send an authentication request)")]
        Authentication = 1,
        /// <summary>
        /// Public server key request (peer will send a public key suite)
        /// </summary>
        [DisplayText("Public server key request (peer will send a public key suite)")]
        PublicKeyRequest = 2,
        /// <summary>
        /// Error response (peer closed the connection)
        /// </summary>
        [DisplayText("Error response (peer closed the connection)")]
        Error = byte.MaxValue
    }
}
