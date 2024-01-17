using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using System.Text.Json.Serialization;
using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// PBKDF#2 KDF algorithm options
    /// </summary>
    public sealed record class KdfPbKdf2Options
    {
        /// <summary>
        /// Default hash algorithm name (SHA3-384)
        /// </summary>
        public const string DEFAULT_HASH_ALGORITHM = HashSha384Algorithm.ALGORITHM_NAME;

        /// <summary>
        /// Hash algorithm name
        /// </summary>
        private string _HashAlgorithm = DefaultHashAlgorithm;

        /// <summary>
        /// Constructor
        /// </summary>
        public KdfPbKdf2Options() { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="json">JSON string</param>
        public KdfPbKdf2Options(string json)
        {
            KdfPbKdf2Options options = (json ?? throw new ArgumentException("Invalid JSON data", nameof(json)))!;
            HashAlgorithm = options.HashAlgorithm;
        }

        /// <summary>
        /// Default hash algorithm name
        /// </summary>
        public static string DefaultHashAlgorithm { get; set; } = DEFAULT_HASH_ALGORITHM;

        /// <summary>
        /// Hash algorithm name
        /// </summary>
        [Required, MinLength(1), MaxLength(byte.MaxValue)]
        public string HashAlgorithm
        {
            get => _HashAlgorithm;
            set => _HashAlgorithm = value;
        }

        /// <summary>
        /// Hash name
        /// </summary>
        [JsonIgnore, Required]
        public HashAlgorithmName HashName
        {
            get => new(_HashAlgorithm);
            set => _HashAlgorithm = value.Name ?? DefaultHashAlgorithm;
        }

        /// <summary>
        /// Get a copy of this instance
        /// </summary>
        /// <returns>Instance copy</returns>
        public KdfPbKdf2Options GetCopy() => new()
        {
            _HashAlgorithm = _HashAlgorithm
        };

        /// <inheritdoc/>
        public override string ToString() => this;

        /// <summary>
        /// Cast as JSON string
        /// </summary>
        /// <param name="options">Options</param>
        public static implicit operator string(KdfPbKdf2Options options) => options.ToJson();

        /// <summary>
        /// Cast as options
        /// </summary>
        /// <param name="json">JSON string</param>
        public static implicit operator KdfPbKdf2Options?(string? json)
            => json is null ? null : json.DecodeJson<KdfPbKdf2Options>() ?? throw new InvalidDataException("Invalid JSON data");

        /// <summary>
        /// Cast as <see cref="CryptoOptions"/>
        /// </summary>
        /// <param name="options">Options</param>
        public static implicit operator CryptoOptions(KdfPbKdf2Options options) => new()
        {
            KdfAlgorithm = KdfPbKdf2Algorithm.ALGORITHM_NAME,
            KdfIterations = KdfPbKdf2Algorithm.Instance.DefaultIterations,
            KdfOptions = options
        };
    }
}
