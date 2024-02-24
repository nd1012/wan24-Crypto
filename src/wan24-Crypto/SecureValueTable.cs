using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Secure value table
    /// </summary>
    public static class SecureValueTable
    {
        /// <summary>
        /// Values (key is the GUID)
        /// </summary>
        public static readonly ConcurrentChangeTokenDictionary<string, SecureValue> Values = [];
    }
}
