using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using System.Text.Json.Serialization;
using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// SP 800-108 HMAC CTR KBKDF algorithm options
    /// </summary>
    public sealed record class KdfSp800_801HmacKbKdfOptions
    {
        /// <summary>
        /// Default hash algorithm name (SHA3-384)
        /// </summary>
        public const string DEFAULT_HASH_ALGORITHM = HashSha3_384Algorithm.ALGORITHM_NAME;

        /// <summary>
        /// Hash algorithm name
        /// </summary>
        private string _HashAlgorithm = DefaultHashAlgorithm;

        /// <summary>
        /// Constructor
        /// </summary>
        public KdfSp800_801HmacKbKdfOptions() { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="json">JSON string</param>
        public KdfSp800_801HmacKbKdfOptions(in string json)
        {
            KdfSp800_801HmacKbKdfOptions options = (json ?? throw new ArgumentException("Invalid JSON data", nameof(json)))!;
            HashAlgorithm = options.HashAlgorithm;
            Label = options.Label;
            Context = options.Context;
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
        [JsonIgnore]
        public HashAlgorithmName HashName
        {
            get => new(_HashAlgorithm);
            set => _HashAlgorithm = value.Name ?? DefaultHashAlgorithm;
        }

        /// <summary>
        /// Label
        /// </summary>
        [MaxLength(byte.MaxValue)]
        public string Label { get; set; } = string.Empty;

        /// <summary>
        /// Context
        /// </summary>
        [MaxLength(byte.MaxValue)]
        public string Context { get; set; } = string.Empty;

        /// <summary>
        /// Get a copy of this instance
        /// </summary>
        /// <returns>Instance copy</returns>
        public KdfSp800_801HmacKbKdfOptions GetCopy() => new()
        {
            _HashAlgorithm = _HashAlgorithm,
            Label = Label,
            Context = Context
        };

        /// <inheritdoc/>
        public override string ToString() => this;

        /// <summary>
        /// Cast as JSON string
        /// </summary>
        /// <param name="options">Options</param>
        public static implicit operator string(in KdfSp800_801HmacKbKdfOptions options) => options.ToJson();

        /// <summary>
        /// Cast as options
        /// </summary>
        /// <param name="json">JSON string</param>
        public static implicit operator KdfSp800_801HmacKbKdfOptions?(in string? json)
            => json is null ? null : json.DecodeJson<KdfSp800_801HmacKbKdfOptions>() ?? throw new InvalidDataException("Invalid JSON data");

        /// <summary>
        /// Cast as <see cref="CryptoOptions"/>
        /// </summary>
        /// <param name="options">Options</param>
        public static implicit operator CryptoOptions(in KdfSp800_801HmacKbKdfOptions options) => new()
        {
            KdfAlgorithm = KdfSp800_108HmacCtrKbKdfAlgorithm.ALGORITHM_NAME,
            KdfIterations = 0,
            KdfOptions = options
        };
    }
}
