using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Disposable <see cref="CryptoOptions"/> (will clear the hosted options when disposing)
    /// </summary>
    public sealed record class DisposableCryptoOptions : DisposableRecordBase
    {
        /// <summary>
        /// Options
        /// </summary>
        private readonly CryptoOptions _Options;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="options">Options</param>
        public DisposableCryptoOptions(in CryptoOptions? options = null) : base(asyncDisposing: false) => _Options = options ?? new();

        /// <summary>
        /// Options
        /// </summary>
        public CryptoOptions Options => IfUndisposed(_Options);

        /// <inheritdoc/>
        protected override void Dispose(bool disposing) => _Options.Clear();

        /// <summary>
        /// Cast as <see cref="CryptoOptions"/>
        /// </summary>
        /// <param name="options"><see cref="DisposableCryptoOptions"/></param>
        public static implicit operator CryptoOptions(in DisposableCryptoOptions options) => options.Options;

        /// <summary>
        /// Cast as <see cref="DisposableCryptoOptions"/>
        /// </summary>
        /// <param name="options"><see cref="CryptoOptions"/></param>
        public static implicit operator DisposableCryptoOptions(in CryptoOptions options) => new(options);
    }
}
