using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Process secret
    /// </summary>
    /// <remarks>
    /// Constructor
    /// </remarks>
    /// <param name="value">Raw value (will be cleared!)</param>
    /// <param name="encryptTimeout">Encrypt timeout (<see cref="TimeSpan.Zero"/> to keep encrypted all the time)</param>
    /// <param name="recryptTimeout">Re-crypt timeout (one minute, for example)</param>
    /// <param name="options">Options (will be cleared!)</param>
    public sealed class ProcessSecret(
        in byte[] value,
        in TimeSpan? encryptTimeout = null,
        in TimeSpan? recryptTimeout = null,
        in CryptoOptions? options = null
        )
        : DisposableBase()
    {
        /// <summary>
        /// Value
        /// </summary>
        private readonly SecureValue _Value = new(value, encryptTimeout, recryptTimeout, options);

        /// <summary>
        /// Value (will/should be cleared!)
        /// </summary>
        public byte[] Value
        {
            get => IfUndisposed(() => _Value.Value);
            set => IfUndisposed(() => _Value.Value = value);
        }

        /// <summary>
        /// Get a storable value
        /// </summary>
        /// <returns>Storable value</returns>
        public byte[] GetStorableValue()
        {
            EnsureUndisposed();
            using SecureByteArray secureValue = new(Value);
            return ValueProtection.Protect(secureValue.Array, ValueProtection.Scope.Process);
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing) => _Value.Dispose();

        /// <inheritdoc/>
        protected override async Task DisposeCore() => await _Value.DisposeAsync().DynamicContext();

        /// <summary>
        /// Create from stored value
        /// </summary>
        /// <param name="value">Stored value</param>
        /// <param name="encryptTimeout">Encrypt timeout (<see cref="TimeSpan.Zero"/> to keep encrypted all the time)</param>
        /// <param name="recryptTimeout">Re-crypt timeout (one minute, for example)</param>
        /// <param name="options">Options (will be cleared!)</param>
        /// <returns>Instance</returns>
        public static ProcessSecret FromStoredValue(
            in byte[] value,
            in TimeSpan? encryptTimeout = null,
            in TimeSpan? recryptTimeout = null,
            in CryptoOptions? options = null
            )
            => new(ValueProtection.Unprotect(value, ValueProtection.Scope.Process), encryptTimeout, recryptTimeout, options);
    }
}
