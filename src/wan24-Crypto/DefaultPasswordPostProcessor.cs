using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Default password post-processor (performs KDF, can perform counter KDF and MAC (if a counter MAC algorthm was set); resulting password will be 64 bytes, or the length of the counter MAC 
    /// algorithm)
    /// </summary>
    public sealed class DefaultPasswordPostProcessor : PasswordPostProcessor
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public DefaultPasswordPostProcessor() : base() { }

        /// <summary>
        /// Options (require MAC and KDF algorithm)
        /// </summary>
        public static CryptoOptions Options => new CryptoOptions()
            .WithMac()
            .WithKdf();

        /// <inheritdoc/>
        public override byte[] PostProcess(byte[] pwd) => PostProcess(pwd, Options);

        /// <summary>
        /// Post-process a password with custom options
        /// </summary>
        /// <param name="pwd">Password (won't be cleared)</param>
        /// <param name="options">Options</param>
        /// <returns>Processed password (don't forget to clear!)</returns>
        public static byte[] PostProcess(in byte[] pwd, CryptoOptions options)
        {
            if (options.MacAlgorithm is null) throw new ArgumentException("Missing MAC algorithm", nameof(options));
            if (options.KdfAlgorithm is null) throw new ArgumentException("Missing KDF algorithm", nameof(options));
            options = options.GetCopy();
            // KDF
            using SecureByteArrayRefStruct salt = new(pwd.Mac(pwd, options));
            (options.Password, options.CounterKdfSalt) = pwd.Stretch(HashSha3_512Algorithm.HASH_LENGTH, salt.Array, options);
            if (options.CounterKdfAlgorithm is not null)
                try
                {
                    HybridAlgorithmHelper.StretchPassword(options);
                }
                catch (Exception ex)
                {
                    options.Clear();
                    if (ex is CryptographicException) throw;
                    else throw CryptographicException.From(ex);
                }
            if (options.CounterMacAlgorithm is null) return options.Password;
            // MAC
            using SecureByteArrayRefStruct stretchedPwd = new(options.Password);
            return salt.Span.Mac(options.Password, new CryptoOptions().WithMac(options.CounterMacAlgorithm));
        }
    }
}
