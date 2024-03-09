using System.ComponentModel.DataAnnotations;
using wan24.Core;
using static wan24.Core.TranslationHelper;

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
        public virtual IEnumerable<Status> State
        {
            get
            {
                yield return new(__("Type"), GetType(), __("Algorithm CLR type"));
                yield return new(__("Display name"), DisplayName, __("Algorithm display name"));
                yield return new(__("Name"), Name, __("Algorithm name"));
                yield return new(__("Value"), Value, __("Algorithm value"));
                yield return new(__("PQC"), IsPostQuantum, __("If the algorithm is post quantum-safe"));
                yield return new(__("TPM"), UsesTpm, __("If the algorithm uses TPM hardware"));
                yield return new(__("Supported"), IsSupported, __("If the algorithm is supported in the current app environment"));
            }
        }

        /// <inheritdoc/>
        public virtual bool EnsureAllowed(in bool throwIfDenied = true) => EnsurePqcRequirement(throwIfDenied);

        /// <inheritdoc/>
        public override string ToString() => $"Cryptographic algorithm \"{DisplayName}\" (\"{Name}\", {Value}) {GetType()}";

        /// <summary>
        /// Ensure PQC requirement
        /// </summary>
        /// <param name="throwIfRequirementMismatch">Throw an axception if the PQC requirement does not match</param>
        /// <returns></returns>
        /// <exception cref="CryptographicException">The PQC requirement does not match</exception>
        protected virtual bool EnsurePqcRequirement(in bool throwIfRequirementMismatch = true)
        {
            if (!IsPostQuantum && CryptoHelper.StrictPostQuantumSafety)
            {
                if (!throwIfRequirementMismatch) return false;
                throw CryptographicException.From(new InvalidOperationException($"Post quantum safety-forced - {DisplayName} isn't post quantum-safe"));
            }
            return true;
        }
    }
}
