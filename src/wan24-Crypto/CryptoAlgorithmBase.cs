using System.ComponentModel.DataAnnotations;

namespace wan24.Crypto
{
    /// <summary>
    /// Base class for a cryptographic algorithm
    /// </summary>
    public abstract record class CryptoAlgorithmBase : ICryptoAlgorithm
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
        [StringLength(byte.MaxValue)]
        public string Name { get; }

        /// <inheritdoc/>
        [Range(0, int.MaxValue)]
        public int Value { get; }

        /// <inheritdoc/>
        public abstract bool IsPostQuantum { get; }

        /// <inheritdoc/>
        public virtual bool UsesTpm => false;

        /// <inheritdoc/>
        public virtual bool IsSupported => true;

        /// <inheritdoc/>
        public virtual string DisplayName => Name;

        /// <inheritdoc/>
        public override string ToString() => $"Cryptographic algorithm \"{DisplayName}\" (\"{Name}\", {Value}) {GetType()}";
    }
}
