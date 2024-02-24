using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Fast PAKE server table
    /// </summary>
    public static class FastPakeAuthServerTable
    {
        /// <summary>
        /// Servers (key is the GUID)
        /// </summary>
        public static readonly ConcurrentChangeTokenDictionary<string, FastPakeAuthServer> Servers = [];
    }
}
