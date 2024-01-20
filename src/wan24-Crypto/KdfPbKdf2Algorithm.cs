using System.Security.Cryptography;

namespace wan24.Crypto
{
    /// <summary>
    /// PBKDF#2 KDF algorithm
    /// </summary>
    public sealed record class KdfPbKdf2Algorithm : KdfAlgorithmBase
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "PBKDF2";
        /// <summary>
        /// Algorithm value
        /// </summary>
        public const int ALGORITHM_VALUE = 0;
        /// <summary>
        /// Default iterations
        /// </summary>
        public const int DEFAULT_ITERATIONS = 250_000;
        /// <summary>
        /// Min. iterations
        /// </summary>
        public const int MIN_ITERATIONS = 210_000;
        /// <summary>
        /// Default salt bytes length
        /// </summary>
        public const int DEFAULT_SALT_LEN = 16;
        /// <summary>
        /// Min. salt bytes length
        /// </summary>
        public const int MIN_SALT_LEN = 16;
        /// <summary>
        /// Display name
        /// </summary>
        public const string DISPLAY_NAME = "PBKDF#2";

        /// <summary>
        /// Default iterations
        /// </summary>
        private int _DefaultIterations = DEFAULT_ITERATIONS;

        /// <summary>
        /// Static constructor
        /// </summary>
        static KdfPbKdf2Algorithm() => Instance = new();

        /// <summary>
        /// Constructor
        /// </summary>
        public KdfPbKdf2Algorithm() : base(ALGORITHM_NAME, ALGORITHM_VALUE)
        {
            _DefaultOptions.KdfAlgorithm = ALGORITHM_NAME;
            _DefaultOptions.KdfIterations = DEFAULT_ITERATIONS;
            _DefaultOptions.KdfAlgorithmIncluded = true;
        }

        /// <summary>
        /// Instance
        /// </summary>
        public static KdfPbKdf2Algorithm Instance { get; }

        /// <inheritdoc/>
        public override CryptoOptions DefaultOptions
        {
            get
            {
                CryptoOptions res = base.DefaultOptions;
                res.HashAlgorithm = KdfPbKdf2Options.DefaultHashAlgorithm;
                return res;
            }
        }

        /// <inheritdoc/>
        public override int MinIterations => MIN_ITERATIONS;

        /// <inheritdoc/>
        public override int DefaultIterations
        {
            get => _DefaultIterations;
            set
            {
                ArgumentOutOfRangeException.ThrowIfLessThan(value, MIN_ITERATIONS);
                _DefaultIterations = value;
            }
        }

        /// <inheritdoc/>
        public override int MinSaltLength => MIN_SALT_LEN;

        /// <inheritdoc/>
        public override int SaltLength => DEFAULT_SALT_LEN;

        /// <inheritdoc/>
        public override bool IsPostQuantum => true;

        /// <inheritdoc/>
        public override string DisplayName => DISPLAY_NAME;

        /// <inheritdoc/>
        public override (byte[] Stretched, byte[] Salt) Stretch(byte[] pwd, int len, byte[]? salt = null, CryptoOptions? options = null)
        {
            try
            {
                ArgumentOutOfRangeException.ThrowIfLessThan(len, 1);
                options = KdfHelper.GetDefaultOptions(options?.GetCopy() ?? DefaultOptions);
                if (options.KdfIterations < MIN_ITERATIONS) throw new ArgumentException("Invalid KDF iterations", nameof(options));
                salt ??= RND.GetBytes(DEFAULT_SALT_LEN);
                if (salt.Length < MIN_SALT_LEN) throw new ArgumentException("Invalid salt length", nameof(salt));
                options.KdfOptions ??= new KdfPbKdf2Options();
                KdfPbKdf2Options kdfOptions = options.KdfOptions!;
                using Rfc2898DeriveBytes kdf = new(pwd, salt, options.KdfIterations, kdfOptions.HashName);
                return (kdf.GetBytes(len), salt);
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }
    }
}
