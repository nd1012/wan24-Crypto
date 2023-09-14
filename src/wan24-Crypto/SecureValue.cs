using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Secure value (keeps a value encrypted after a timeout, re-crypts from time to time)
    /// </summary>
    public sealed class SecureValue : DisposableBase
    {
        /// <summary>
        /// Encrypt timer
        /// </summary>
        private readonly System.Timers.Timer EncryptTimer;
        /// <summary>
        /// Recrypt timer
        /// </summary>
        private readonly System.Timers.Timer RecryptTimer;
        /// <summary>
        /// Thread synchronization
        /// </summary>
        private readonly SemaphoreSync Sync = new();
        /// <summary>
        /// Raw value
        /// </summary>
        private SecureByteArray? RawValue;
        /// <summary>
        /// Encrypted value
        /// </summary>
        private SecureByteArray? EncryptedValue = null;
        /// <summary>
        /// Encryption key
        /// </summary>
        private SecureByteArray? EncryptionKey = null;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="value">Value (will be cleared!)</param>
        /// <param name="encryptTimeout">Encrypt timeout (<see cref="TimeSpan.Zero"/> to keep encrypted all the time)</param>
        /// <param name="recryptTimeout">Re-crypt timeout (see <see href="https://static.usenix.org/events/sec01/full_papers/gutmann/gutmann.pdf"/>: "...there's enough risk to 
        /// dispose the RAM carefully...")</param>
        /// <param name="options">Options</param>
        public SecureValue(byte[] value, TimeSpan encryptTimeout, TimeSpan recryptTimeout, CryptoOptions? options = null) : base(asyncDisposing: false)
        {
            RawValue = new(value);
            EncryptTimeout = encryptTimeout;
            RecryptTimeout = recryptTimeout;
            Options = options ?? new();
            if (Options.Algorithm is null) Options.WithEncryptionAlgorithm();
            EncryptTimer = new()
            {
                Interval = encryptTimeout.TotalMilliseconds,
                AutoReset = false
            };
            EncryptTimer.Elapsed += (s, e) => Encrypt();
            RecryptTimer = new()
            {
                Interval = recryptTimeout.TotalMilliseconds,
                AutoReset = false
            };
            RecryptTimer.Elapsed += (s, e) => Recrypt();
            if (encryptTimeout == TimeSpan.Zero)
            {
                Encrypt(sync: false);
            }
            else
            {
                EncryptTimer.Start();
            }
        }

        /// <summary>
        /// Value (should be cleared / will be cleared!)
        /// </summary>
        public byte[] Value
        {
            get
            {
                EnsureUndisposed();
                using SemaphoreSyncContext ssc = Sync.SyncContext();
                if (RawValue is null) return Decrypt();
                RecryptTimer.Stop();
                EncryptTimer.Stop();
                EncryptTimer.Start();
                RecryptTimer.Start();
                return RawValue.Array.CloneArray();
            }
            set
            {
                EnsureUndisposed();
                using SemaphoreSyncContext ssc = Sync.SyncContext();
                RecryptTimer.Stop();
                EncryptTimer.Stop();
                if (RawValue is null)
                {
                    EncryptedValue!.Dispose();
                    EncryptionKey!.Dispose();
                    if (EncryptTimeout == TimeSpan.Zero)
                    {
                        EncryptionKey = new(RND.GetBytes(64));
                        EncryptedValue = new(value.Encrypt(EncryptionKey.Array, Options));
                        RecryptTimer.Start();
                        value.Clear();
                        return;
                    }
                    else
                    {
                        EncryptedValue = null;
                        EncryptionKey = null;
                    }
                }
                RawValue?.Dispose();
                RawValue = new(value);
                EncryptTimer.Start();
                RecryptTimer.Start();
            }
        }

        /// <summary>
        /// Options
        /// </summary>
        public CryptoOptions Options { get; }

        /// <summary>
        /// Encrypt timeout
        /// </summary>
        public TimeSpan EncryptTimeout { get; }

        /// <summary>
        /// Recrypt timeout (see <see href="https://static.usenix.org/events/sec01/full_papers/gutmann/gutmann.pdf"/>: "...there's enough risk to dispose the RAM carefully...")
        /// </summary>
        public TimeSpan RecryptTimeout { get; }

        /// <summary>
        /// Get the value
        /// </summary>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Value (should be cleared!)</returns>
        public async Task<byte[]> GetValueAsync(CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = await Sync.SyncContextAsync(cancellationToken).DynamicContext();
            if (RawValue is null) return Decrypt();
            RecryptTimer.Stop();
            EncryptTimer.Stop();
            EncryptTimer.Start();
            RecryptTimer.Start();
            return RawValue.Array.CloneArray();
        }

        /// <summary>
        /// Set the value
        /// </summary>
        /// <param name="value">Value (will be cleared!)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        public async Task SetValueAsync(byte[] value, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = await Sync.SyncContextAsync(cancellationToken).DynamicContext();
            RecryptTimer.Stop();
            EncryptTimer.Stop();
            if (RawValue is null)
            {
                EncryptedValue!.Dispose();
                EncryptionKey!.Dispose();
                if (EncryptTimeout == TimeSpan.Zero)
                {
                    EncryptionKey = new(await RND.GetBytesAsync(64).DynamicContext());
                    EncryptedValue = new(value.Encrypt(EncryptionKey.Array, Options));
                    RecryptTimer.Start();
                    value.Clear();
                    return;
                }
                else
                {
                    EncryptedValue = null;
                    EncryptionKey = null;
                }
            }
            RawValue?.Dispose();
            RawValue = new(value);
            EncryptTimer.Start();
            RecryptTimer.Start();
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            using (SemaphoreSyncContext ssc = Sync.SyncContext())
            {
                RecryptTimer.Stop();
                RecryptTimer.Dispose();
                EncryptTimer.Stop();
                EncryptTimer.Dispose();
                RawValue?.Dispose();
                RawValue = null;
                EncryptionKey?.Dispose();
                EncryptionKey = null;
                EncryptedValue?.Dispose();
                EncryptedValue = null;
            }
            Sync.Dispose();
        }

        /// <summary>
        /// Encrypt
        /// </summary>
        /// <param name="sync">Thread synchronization?</param>
        private void Encrypt(bool sync = true)
        {
            using SemaphoreSyncContext? ssc = sync ? Sync.SyncContext() : null;
            if (RawValue is null) return;
            EncryptTimer.Stop();
            EncryptionKey = new(RND.GetBytes(64));
            EncryptedValue = new(RawValue!.Array.Encrypt(EncryptionKey.Array, Options));
            RawValue.Dispose();
            RawValue = null;
            RecryptTimer.Start();
        }

        /// <summary>
        /// Decrypt
        /// </summary>
        /// <param name="sync">Thread synchronization?</param>
        /// <returns>Value (should be cleared!)</returns>
        private byte[] Decrypt(bool sync = false)
        {
            using SemaphoreSyncContext? ssc = sync ? Sync.SyncContext() : null;
            if (RawValue is not null) return RawValue.Array.CloneArray();
            if (EncryptTimeout == TimeSpan.Zero)
                return EncryptedValue!.Array.Decrypt(EncryptionKey!.Array, Options);
            RecryptTimer.Stop();
            RawValue = new(EncryptedValue!.Array.Decrypt(EncryptionKey!.Array, Options));
            EncryptedValue.Dispose();
            EncryptedValue = null;
            EncryptionKey.Dispose();
            EncryptionKey = null;
            EncryptTimer.Start();
            return RawValue.Array.CloneArray();
        }

        /// <summary>
        /// Re-crypt
        /// </summary>
        private void Recrypt()
        {
            using SemaphoreSyncContext ssc = Sync.SyncContext();
            if (RawValue is not null) return;
            RecryptTimer.Stop();
            byte[] rawValue = EncryptedValue!.Array.Decrypt(EncryptionKey!.Array, Options);
            EncryptedValue.Dispose();
            SecureByteArray newEncryptionKey = new(RND.GetBytes(64));
            EncryptedValue = new(rawValue.Encrypt(newEncryptionKey.Array, Options));
            EncryptionKey.Dispose();
            EncryptionKey = newEncryptionKey;
            RecryptTimer.Start();
        }

        /// <summary>
        /// Cast as value
        /// </summary>
        /// <param name="value">Value (should be cleared!)</param>
        public static implicit operator byte[](SecureValue value) => value.Value;
    }
}
