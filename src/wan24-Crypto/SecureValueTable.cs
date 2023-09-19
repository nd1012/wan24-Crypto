using System.Collections.Concurrent;

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
        public static readonly ConcurrentDictionary<string, SecureValue> Values = new();
    }
}
