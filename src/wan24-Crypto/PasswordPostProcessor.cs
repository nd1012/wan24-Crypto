namespace wan24.Crypto
{
    /// <summary>
    /// Base class for a password post-processor
    /// </summary>
    public abstract class PasswordPostProcessor
    {
        /// <summary>
        /// Constructor
        /// </summary>
        protected PasswordPostProcessor() { }

        /// <summary>
        /// Default instance to use
        /// </summary>
        public static PasswordPostProcessor Instance { get; set; } = new DefaultPasswordPostProcessor();

        /// <summary>
        /// Post-process a password
        /// </summary>
        /// <param name="pwd">Password (won't be cleared)</param>
        /// <returns>Processed password (don't forget to clear!)</returns>
        public abstract byte[] PostProcess(byte[] pwd);

        /// <summary>
        /// A <see cref="CryptoOptions.EncryptionPasswordPreProcessor_Delegate"/> for pre-processing an encryption password
        /// </summary>
        /// <param name="algo">Encryption algorithm</param>
        /// <param name="options">Options</param>
        public virtual void PreProcessEncryptionPassword(EncryptionAlgorithmBase algo, CryptoOptions options)
        {
            if (options.Password is null) throw new ArgumentException("Password not set", nameof(options));
            options.SetNewPassword(PostProcess(options.Password));
        }

        /// <summary>
        /// A <see cref="CryptoOptions.AsyncEncryptionPasswordPreProcessor_Delegate"/> for pre-processing an encryption password
        /// </summary>
        /// <param name="algo">Encryption algorithm</param>
        /// <param name="options">Options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        [Obsolete("Use PreProcessEncryptionPasswordAsync instead")]//TODO Remove in v3
        public Task PreProcessAsyncEncryptionPassword(EncryptionAlgorithmBase algo, CryptoOptions options, CancellationToken cancellationToken)
            => PreProcessEncryptionPasswordAsync(algo, options, cancellationToken);

        /// <summary>
        /// A <see cref="CryptoOptions.AsyncEncryptionPasswordPreProcessor_Delegate"/> for pre-processing an encryption password
        /// </summary>
        /// <param name="algo">Encryption algorithm</param>
        /// <param name="options">Options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        public virtual Task PreProcessEncryptionPasswordAsync(EncryptionAlgorithmBase algo, CryptoOptions options, CancellationToken cancellationToken)
        {
            if (options.Password is null) throw new ArgumentException("Password not set", nameof(options));
            options.SetNewPassword(PostProcess(options.Password));
            return Task.CompletedTask;
        }
    }
}
