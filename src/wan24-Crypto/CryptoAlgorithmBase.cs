namespace wan24.Crypto
{
    /// <summary>
    /// Base class for a cryptographic algorithm
    /// </summary>
    public abstract class CryptoAlgorithmBase
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="name">Algorithm name</param>
        /// <param name="value">Algorithm value</param>
        protected CryptoAlgorithmBase(string name, int value)
        {
            Name = name;
            Value = value;
        }

        /// <inheritdoc/>
        public string Name { get; }

        /// <inheritdoc/>
        public int Value { get; }

        /// <inheritdoc/>
        public abstract bool IsPostQuantum { get; }
    }
}
