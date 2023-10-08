namespace wan24.Crypto.Authentication
{
    /// <summary>
    /// PAKE authentication server context
    /// </summary>
    public sealed record class PakeServerAuthContext
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="serverAuth">Server authentication</param>
        /// <param name="stream">Stream</param>
        internal PakeServerAuthContext(in PakeServerAuth serverAuth, in Stream stream)
        {
            ServerAuthentication = serverAuth;
            Stream = stream;
        }

        /// <summary>
        /// Server authentication
        /// </summary>
        public PakeServerAuth ServerAuthentication { get; }

        /// <summary>
        /// Stream
        /// </summary>
        public Stream Stream { get; }

        /// <summary>
        /// Client identity
        /// </summary>
        public IPakeRecord? ClientIdentity { get; set; }

        /// <summary>
        /// Server identity
        /// </summary>
        public IPakeAuthRecord? ServerIdentity { get; set; }

        /// <summary>
        /// Fast PAKE authentication server for the peer authentication handling
        /// </summary>
        public FastPakeAuthServer? FastPakeAuthServer { get; set; }

        /// <summary>
        /// Client payload
        /// </summary>
        public PakeClientAuth.AuthPayload? ClientPayload { get; internal set; }

        /// <summary>
        /// Server payload
        /// </summary>
        public byte[]? ServerPayload { get; set; }

        /// <summary>
        /// Client time offset
        /// </summary>
        public TimeSpan? ClientTimeOffset { get; internal set; }
    }
}
