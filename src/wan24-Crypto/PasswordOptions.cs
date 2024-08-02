using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Password options/error flags
    /// </summary>
    [Flags]
    public enum PasswordOptions : byte
    {
        /// <summary>
        /// None
        /// </summary>
        [DisplayText("None")]
        None = 0,
        /// <summary>
        /// Lower case characters
        /// </summary>
        [DisplayText("Lower case characters")]
        Lower = 1,
        /// <summary>
        /// Upper case characters
        /// </summary>
        [DisplayText("Upper case characters")]
        Upper = 2,
        /// <summary>
        /// Numeric characters
        /// </summary>
        [DisplayText("Numeric characters")]
        Numeric = 4,
        /// <summary>
        /// Special characters
        /// </summary>
        [DisplayText("Special characters")]
        Special = 8,
        /// <summary>
        /// Invalid length
        /// </summary>
        [DisplayText("Invalid password length")]
        Length = 16,
        /// <summary>
        /// Not enough entropy
        /// </summary>
        [DisplayText("Not enough password entropy")]
        Entropy = 32
    }
}
