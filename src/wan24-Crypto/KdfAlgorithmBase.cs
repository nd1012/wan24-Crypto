namespace wan24.Crypto
{
    /// <summary>
    /// Base class for a KDF algorithm
    /// </summary>
    public abstract class KdfAlgorithmBase : CryptoAlgorithmBase
    {
        /// <summary>
        /// Default options
        /// </summary>
        protected readonly CryptoOptions _DefaultOptions;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="name">Algorithm name</param>
        /// <param name="value">Algorithm value</param>
        protected KdfAlgorithmBase(string name, int value) : base(name, value)
            => _DefaultOptions = new()
            {
                KdfAlgorithm = Name,
                KdfIterations = DefaultIterations
            };

        /// <summary>
        /// Default options
        /// </summary>
        public virtual CryptoOptions DefaultOptions => _DefaultOptions.Clone().WithKdf(Name, DefaultIterations, DefaultKdfOptions);

        /// <summary>
        /// Default number of iterations
        /// </summary>
        public abstract int DefaultIterations { get; set; }

        /// <summary>
        /// Default KDF options
        /// </summary>
        public string? DefaultKdfOptions { get; set; }

        /// <summary>
        /// Salt length in bytes
        /// </summary>
        public abstract int SaltLength { get; }

        /// <summary>
        /// Stretch a password
        /// </summary>
        /// <param name="pwd">Password</param>
        /// <param name="len">Required password length</param>
        /// <param name="salt">Salt</param>
        /// <param name="options">Options</param>
        /// <returns>Stretched password and the used salt</returns>
        public abstract (byte[] Stretched, byte[] Salt) Stretch(byte[] pwd, int len, byte[]? salt = null, CryptoOptions? options = null);

        /// <summary>
        /// Validate KDF options for this algorithm
        /// </summary>
        /// <param name="kdfOptions">KDF options</param>
        /// <param name="throwOnError">Throw an exception on error?</param>
        /// <returns>If the options are valid</returns>
        public virtual bool ValidateOptions(string? kdfOptions, bool throwOnError = true)
        {
            if (kdfOptions != null)
            {
                if (throwOnError) throw new CryptographicException($"KDF options for {Name} aren't upported and should be NULL");
                return false;
            }
            return true;
        }
    }
}
