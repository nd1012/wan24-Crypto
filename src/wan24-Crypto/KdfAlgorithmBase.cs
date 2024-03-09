using wan24.Core;
using static wan24.Core.TranslationHelper;

namespace wan24.Crypto
{
    /// <summary>
    /// Base class for a KDF algorithm
    /// </summary>
    public abstract record class KdfAlgorithmBase : CryptoAlgorithmBase
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
                KdfIterations = DefaultIterations,
                KdfOptions = DefaultKdfOptions
            };

        /// <summary>
        /// Default options
        /// </summary>
        public virtual CryptoOptions DefaultOptions => KdfHelper.GetDefaultOptions(_DefaultOptions.GetCopy());

        /// <summary>
        /// Minimum number of iterations
        /// </summary>
        public abstract int MinIterations { get; }

        /// <summary>
        /// Default number of iterations
        /// </summary>
        public abstract int DefaultIterations { get; set; }

        /// <summary>
        /// Default KDF options
        /// </summary>
        public string? DefaultKdfOptions { get; set; }

        /// <summary>
        /// Minimum salt length in bytes
        /// </summary>
        public abstract int MinSaltLength { get; }

        /// <summary>
        /// Salt length in bytes
        /// </summary>
        public abstract int SaltLength { get; }

        /// <inheritdoc/>
        public override IEnumerable<Status> State
        {
            get
            {
                foreach (Status status in base.State) yield return status;
                yield return new(__("Min. iterations"), MinIterations, __("The minimum number of iterations"));
                yield return new(__("DefaultIterations"), DefaultIterations, __("The default number of iterations"));
                yield return new(__("Options"), DefaultKdfOptions is not null, __("If the algorithm can be configured using an options object"));
                yield return new(__("Min. salt length"), MinSaltLength, __("The minimum salt length in bytes"));
                yield return new(__("Salt length"), SaltLength, __("The default salt length in bytes"));
            }
        }

        /// <summary>
        /// Ensure that the given options include the default options for this algorithm
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>Options</returns>
        public virtual CryptoOptions EnsureDefaultOptions(CryptoOptions? options = null)
        {
            if (options is null) return DefaultOptions;
            options.KdfAlgorithm = _DefaultOptions.KdfAlgorithm;
            options.KdfIterations = DefaultIterations;
            options.KdfOptions = DefaultKdfOptions;
            return options;
        }

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
            if (kdfOptions is not null)
            {
                if (throwOnError) throw new CryptographicException($"KDF options for {Name} aren't supported and should be NULL");
                return false;
            }
            return true;
        }
    }
}
