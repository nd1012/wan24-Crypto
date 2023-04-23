using System.Security.Cryptography;

namespace wan24.Crypto
{
    /// <summary>
    /// PBKDF#2 KDF algorithm
    /// </summary>
    public sealed class KdfPbKdf2Algorithm : KdfAlgorithmBase
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
        public const int DEFAULT_ITERATIONS = 20000;
        /// <summary>
        /// Default salt bytes length
        /// </summary>
        public const int DEFAULT_SALT_LEN = 8;

        /// <summary>
        /// Default iterations
        /// </summary>
        private int _DefaultIterations = DEFAULT_ITERATIONS;

        /// <summary>
        /// Constructor
        /// </summary>
        public KdfPbKdf2Algorithm() : base(ALGORITHM_NAME, ALGORITHM_VALUE) { }

        /// <summary>
        /// Default iterations
        /// </summary>
        public override int DefaultIterations
        {
            get => _DefaultIterations;
            set
            {
                if (value < DEFAULT_ITERATIONS) throw new ArgumentOutOfRangeException(nameof(value));
                _DefaultIterations = value;
            }
        }

        /// <inheritdoc/>
        public override int SaltLength => DEFAULT_SALT_LEN;

        /// <inheritdoc/>
        public override (byte[] Stretched, byte[] Salt) Stretch(byte[] pwd, int len, byte[]? salt = null, CryptoOptions? options = null)
        {
            try
            {
                if (len < 1) throw new ArgumentOutOfRangeException(nameof(len));
                options ??= DefaultOptions;
                if (options.KdfIterations < DEFAULT_ITERATIONS) throw new ArgumentException("Invalid KDF iterations", nameof(options));
                salt ??= RandomNumberGenerator.GetBytes(DEFAULT_SALT_LEN);
                if (salt.Length < DEFAULT_SALT_LEN) throw new ArgumentException("Invalid salt length", nameof(salt));
                using Rfc2898DeriveBytes kdf = new(pwd, salt, options.KdfIterations);
                return (kdf.GetBytes(len), salt);
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw new CryptographicException(ex.Message, ex);
            }
        }
    }
}
