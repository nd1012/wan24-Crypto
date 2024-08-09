using System.Text;
using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Password helper
    /// </summary>
    public static class PasswordHelper
    {
        /// <summary>
        /// Lower case characters
        /// </summary>
        public const string LOWER = "abcdefghijklmnopqrstuvwxyz";
        /// <summary>
        /// Upper case characters
        /// </summary>
        public const string UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        /// <summary>
        /// Numeric characters
        /// </summary>
        public const string NUMERIC = "0123456789";
        /// <summary>
        /// Special characters
        /// </summary>
        public const string SPECIAL = "!\"§$%&/()=?@<+#-.,{[]}\\>*'_:;^~|";

        /// <summary>
        /// Max. tries for generating a password using the specified options (see <see cref="GeneratePassword(int?, PasswordOptions?, bool?, string?, string?, string?, string?)"/>)
        /// </summary>
        public static int MaxTries { get; set; } = 32;

        /// <summary>
        /// Default password options
        /// </summary>
        public static PasswordOptions DefaultOptions { get; set; } = PasswordOptions.Lower | PasswordOptions.Upper | PasswordOptions.Numeric | PasswordOptions.Special;

        /// <summary>
        /// Default password length in characters
        /// </summary>
        public static int DefaultLength { get; set; } = 32;

        /// <summary>
        /// If to check the password entropy per default (see <see cref="EntropyHelper.CheckEntropy(in ReadOnlySpan{byte}, EntropyHelper.Algorithms?, in bool)"/>)
        /// </summary>
        public static bool DefaultEntropy { get; set; } = true;

        /// <summary>
        /// Default lower case character set (if none, <see cref="LOWER"/> is being used)
        /// </summary>
        public static string? DefaultLowerCase { get; set; }

        /// <summary>
        /// Default upper case character set (if none, <see cref="UPPER"/> is being used)
        /// </summary>
        public static string? DefaultUpperCase { get; set; }

        /// <summary>
        /// Default numeric character set (if none, <see cref="NUMERIC"/> is being used)
        /// </summary>
        public static string? DefaultNumeric { get; set; }

        /// <summary>
        /// Default special character set (if none, <see cref="SPECIAL"/> is being used)
        /// </summary>
        public static string? DefaultSpecial { get; set; }

        /// <summary>
        /// Generate a password
        /// </summary>
        /// <param name="len">Length in characters</param>
        /// <param name="options">Options</param>
        /// <param name="entropy">If to check the entropy using <see cref="EntropyHelper.CheckEntropy(in ReadOnlySpan{byte}, EntropyHelper.Algorithms?, in bool)"/></param>
        /// <param name="lowerCase">Lower case characters to use</param>
        /// <param name="upperCase">Upper case characters to use</param>
        /// <param name="numeric">Numeric characters to use</param>
        /// <param name="special">Special characters to use</param>
        /// <returns>Generated password</returns>
        /// <exception cref="InvalidOperationException">Too many tries (see <see cref="MaxTries"/>)</exception>
        public static char[] GeneratePassword(
            int? len = null,
            PasswordOptions? options = null, 
            bool? entropy = null, 
            string? lowerCase = null, 
            string? upperCase = null,
            string? numeric = null,
            string? special = null
            )
        {
            // Use default options
            len ??= DefaultLength;
            options ??= DefaultOptions;
            // Validate options
            if (len.Value < 1) throw new ArgumentOutOfRangeException(nameof(len));
            if ((options.Value & (PasswordOptions.Lower | PasswordOptions.Upper | PasswordOptions.Numeric | PasswordOptions.Special)) == PasswordOptions.None)
                throw new ArgumentException("Invalid options", nameof(options));
            // Prepare password charset
            StringBuilder sb = new();
            if ((options.Value & PasswordOptions.Lower) == PasswordOptions.Lower)
            {
                lowerCase ??= DefaultLowerCase ?? LOWER;
                sb.Append(lowerCase);
            }
            if ((options.Value & PasswordOptions.Upper) == PasswordOptions.Upper)
            {
                upperCase ??= DefaultUpperCase ?? UPPER;
                sb.Append(upperCase);
            }
            if ((options.Value & PasswordOptions.Numeric) == PasswordOptions.Numeric)
            {
                numeric ??= DefaultNumeric ?? NUMERIC;
                sb.Append(numeric);
            }
            if ((options.Value & PasswordOptions.Special) == PasswordOptions.Special)
            {
                special ??= DefaultSpecial ?? SPECIAL;
                sb.Append(special);
            }
            if (sb.Length < 1) throw new InvalidOperationException("No possible password characters");
            string charset = new([.. sb.ToString().OrderBy(c => Rng.GetInt32(int.MinValue, int.MaxValue))]);
            // Generate password
            char[] res = new char[len.Value];
            for (int count = 0; count < MaxTries; count++)
            {
                for (int i = 0; i < res.Length; res[i] = charset[Rng.GetInt32(fromInclusive: 0, toExclusive: charset.Length)], i++) ;
                if (CheckPassword(res, options.Value, minLen: null, maxLen: null, entropy, lowerCase, upperCase, numeric, special) == PasswordOptions.None)
                    return res;
            }
            throw new InvalidOperationException($"Failed to generate a matching password within {MaxTries} tries - giving up");
        }

        /// <summary>
        /// Check a password
        /// </summary>
        /// <param name="pwd">Password (empty password isn't allowed)</param>
        /// <param name="requirements">Requirements</param>
        /// <param name="minLen">Min. length in characters</param>
        /// <param name="maxLen">Max. length in characters</param>
        /// <param name="entropy">If to check the entropy using <see cref="EntropyHelper.CheckEntropy(in ReadOnlySpan{byte}, EntropyHelper.Algorithms?, in bool)"/></param>
        /// <param name="lowerCase">Lower case characters to use</param>
        /// <param name="upperCase">Upper case characters to use</param>
        /// <param name="numeric">Numeric characters to use</param>
        /// <param name="special">Special characters to use</param>
        /// <returns><see cref="PasswordOptions.None"/>, if the password matches the requirements (error flags otherwise)</returns>
        public static PasswordOptions CheckPassword(
            in ReadOnlySpan<char> pwd,
            in PasswordOptions requirements,
            in int? minLen = null,
            in int? maxLen = null,
            in bool? entropy = null,
            in string? lowerCase = null,
            in string? upperCase = null,
            in string? numeric = null,
            in string? special = null
            )
        {
            if (minLen.HasValue)
            {
                if (minLen.Value < 1) throw new ArgumentOutOfRangeException(nameof(minLen));
                if (maxLen.HasValue && maxLen.Value < minLen.Value) throw new ArgumentOutOfRangeException(nameof(maxLen));
            }
            else if (maxLen.HasValue && maxLen.Value < 1)
            {
                throw new ArgumentOutOfRangeException(nameof(maxLen));
            }
            PasswordOptions res = PasswordOptions.None;
            // Length
            if (pwd.Length < 1 || (minLen.HasValue && pwd.Length < minLen.Value) || (maxLen.HasValue && pwd.Length > maxLen.Value)) res |= PasswordOptions.Length;
            // Entropy
            if (entropy.HasValue)
            {
                using SecureByteArrayRefStruct securePwdBytes = new(Encoding.UTF8.GetMaxByteCount(pwd.Length));
                if (!EntropyHelper.CheckEntropy(securePwdBytes.Span[..Encoding.UTF8.GetBytes(pwd, securePwdBytes.Span)])) res |= PasswordOptions.Entropy;
            }
            // Character checks
            if ((requirements & PasswordOptions.Lower) == PasswordOptions.Lower && !pwd.ContainsAny(lowerCase ?? DefaultLowerCase ?? LOWER)) res |= PasswordOptions.Lower;
            if ((requirements & PasswordOptions.Upper) == PasswordOptions.Upper && !pwd.ContainsAny(upperCase ?? DefaultUpperCase ?? UPPER)) res |= PasswordOptions.Upper;
            if ((requirements & PasswordOptions.Numeric) == PasswordOptions.Numeric && !pwd.ContainsAny(numeric ?? DefaultNumeric ?? NUMERIC)) res |= PasswordOptions.Numeric;
            if ((requirements & PasswordOptions.Special) == PasswordOptions.Special && !pwd.ContainsAny(special ?? DefaultSpecial ?? SPECIAL)) res |= PasswordOptions.Special;
            return res;
        }
    }
}
