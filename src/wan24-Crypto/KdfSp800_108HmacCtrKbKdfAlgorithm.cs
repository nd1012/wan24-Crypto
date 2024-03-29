﻿using System.Security.Cryptography;
using wan24.Core;
using static wan24.Core.TranslationHelper;

namespace wan24.Crypto
{
    /// <summary>
    /// SP 800-108 HMAC CTR KBKDF algorithm
    /// </summary>
    public sealed record class KdfSp800_108HmacCtrKbKdfAlgorithm : KdfAlgorithmBase
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "SP800_108HMACCTRKBKDF";
        /// <summary>
        /// Algorithm value
        /// </summary>
        public const int ALGORITHM_VALUE = 2;
        /// <summary>
        /// Display name
        /// </summary>
        public const string DISPLAY_NAME = "SP 800-108 HMAC CTR KBKDF";

        /// <summary>
        /// Static constructor
        /// </summary>
        static KdfSp800_108HmacCtrKbKdfAlgorithm() => Instance = new();

        /// <summary>
        /// Constructor
        /// </summary>
        private KdfSp800_108HmacCtrKbKdfAlgorithm() : base(ALGORITHM_NAME, ALGORITHM_VALUE)
        {
            _DefaultOptions.KdfAlgorithm = ALGORITHM_NAME;
            _DefaultOptions.KdfIterations = 0;
            _DefaultOptions.KdfOptions = new KdfSp800_801HmacKbKdfOptions();
            _DefaultOptions.KdfAlgorithmIncluded = true;
        }

        /// <summary>
        /// Instance
        /// </summary>
        public static KdfSp800_108HmacCtrKbKdfAlgorithm Instance { get; }

        /// <inheritdoc/>
        public override int MinIterations => 0;

        /// <inheritdoc/>
        public override int DefaultIterations
        {
            get => 0;
            set { }
        }

        /// <inheritdoc/>
        public override int MinSaltLength => 0;

        /// <inheritdoc/>
        public override int SaltLength => 0;

        /// <inheritdoc/>
        public override bool IsPostQuantum => true;

        /// <inheritdoc/>
        public override bool IsSupported => !ENV.IsBrowserApp;

        /// <inheritdoc/>
        public override string DisplayName => DISPLAY_NAME;

        /// <inheritdoc/>
        public override IEnumerable<Status> State
        {
            get
            {
                foreach (Status status in base.State) yield return status;
                yield return new(__("Hash"), KdfSp800_801HmacKbKdfOptions.DefaultHashAlgorithm, __("The default hash algorithm name"));
            }
        }

        /// <inheritdoc/>
        public override (byte[] Stretched, byte[] Salt) Stretch(byte[] pwd, int len, byte[]? salt = null, CryptoOptions? options = null)
        {
            try
            {
                EnsureAllowed();
                ArgumentOutOfRangeException.ThrowIfLessThan(len, 1);
                options = KdfHelper.GetDefaultOptions(options?.GetCopy() ?? DefaultOptions);
                options.KdfOptions ??= new KdfSp800_801HmacKbKdfOptions();
                KdfSp800_801HmacKbKdfOptions kdfOptions = options.KdfOptions!;
                using SP800108HmacCounterKdf kdf = new(pwd.AsSpan(), kdfOptions.HashName);
                return (kdf.DeriveKey(kdfOptions.Label, kdfOptions.Context, len), salt ?? []);
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }
    }
}
