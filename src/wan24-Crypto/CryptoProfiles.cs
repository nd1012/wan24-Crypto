using System.Collections.Concurrent;

namespace wan24.Crypto
{
    /// <summary>
    /// Crypto profiles
    /// </summary>
    public static class CryptoProfiles
    {
        /// <summary>
        /// Registered profiles
        /// </summary>
        public static readonly ConcurrentDictionary<string, CryptoOptions> Registered;

        /// <summary>
        /// Constructor
        /// </summary>
        static CryptoProfiles() => Registered = new(new KeyValuePair<string, CryptoOptions>[]
        {
            new(
                EncryptionAes256CbcAlgorithm.PROFILE_AES256CBC_RAW,
                new CryptoOptions()
                    .IncludeNothing()
                    .WithEncryptionAlgorithm(EncryptionAes256CbcAlgorithm.ALGORITHM_VALUE)
                    .WithMac()
                    .WithoutKdf()
                    .WithoutCompression()
                )
        });

        /// <summary>
        /// Get a profile
        /// </summary>
        /// <param name="key">Key</param>
        /// <returns>Profile</returns>
        public static CryptoOptions GetProfile(string key)
            => Registered.TryGetValue(key, out CryptoOptions? res) ? res.Clone() : throw new ArgumentException("Unknown profile", nameof(key));
    }
}
