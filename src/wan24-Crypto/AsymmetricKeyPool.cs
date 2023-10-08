using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Asymmetric private key pool
    /// </summary>
    /// <typeparam name="T">Asymmetric private key type</typeparam>
    public sealed class AsymmetricKeyPool<T> : InstancePool<T>, IAsymmetricKeyPool where T : class, IAsymmetricPrivateKey, new()
    {
        /// <summary>
        /// Algorithm
        /// </summary>
        private static readonly IAsymmetricAlgorithm Algorithm;
        /// <summary>
        /// Options
        /// </summary>
        private readonly CryptoOptions Options;

        /// <summary>
        /// Static constructor
        /// </summary>
        static AsymmetricKeyPool()
        {
            using T key = new();
            Algorithm = key.Algorithm;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="capacity">Capacity</param>
        /// <param name="options">Options</param>
        public AsymmetricKeyPool(in int capacity, in CryptoOptions? options = null) : base(capacity, Factory)
        {
            Options = options ?? Algorithm.DefaultOptions;
            ErrorSource = Constants.CRYPTO_ERROR_SOURCE;
        }

        /// <inheritdoc/>
        IAsymmetricAlgorithm IAsymmetricKeyPool.Algorithm => Algorithm;

        /// <inheritdoc/>
        CryptoOptions IAsymmetricKeyPool.Options => Options.GetCopy();

        /// <inheritdoc/>
        IAsymmetricPrivateKey IAsymmetricKeyPool.GetKey() => GetOne();

        /// <inheritdoc/>
        async Task<IAsymmetricPrivateKey> IAsymmetricKeyPool.GetKeyAsync(CancellationToken cancellationToken)
            => await GetOneAsync(cancellationToken).DynamicContext();

        /// <summary>
        /// Private key factory
        /// </summary>
        /// <param name="pool">Pool</param>
        /// <returns>Private key</returns>
        private static T Factory(IInstancePool<T> pool)
        {
            AsymmetricKeyPool<T> asymmetricKeyPool = (AsymmetricKeyPool<T>)pool;
            return (T)Algorithm.CreateKeyPair(asymmetricKeyPool.Options);
        }
    }
}
