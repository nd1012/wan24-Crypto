using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Secure value (keeps a value encrypted after a timeout without any access, re-crypts from time to time; see 
    /// <see href="https://static.usenix.org/events/sec01/full_papers/gutmann/gutmann.pdf"/>)
    /// </summary>
    public sealed partial class SecureValue : DisposableBase, IStatusProvider
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="value">Value (will be cleared!)</param>
        /// <param name="encryptTimeout">Encrypt timeout (<see cref="TimeSpan.Zero"/> to keep encrypted all the time)</param>
        /// <param name="recryptTimeout">Re-crypt timeout (one minute, for example)</param>
        /// <param name="options">Options (will be cleared!)</param>
        /// <param name="keyLen">Random value encryption key length in bytes</param>
        public SecureValue(
            in byte[] value,
            in TimeSpan? encryptTimeout = null,
            in TimeSpan? recryptTimeout = null,
            in CryptoOptions? options = null,
            in int keyLen = DEFAULT_KEY_LEN
            )
            : base(asyncDisposing: false)
        {
            RawValue = new(value);
            try
            {
                KeyLen = keyLen;
                EncryptTimeout = encryptTimeout ?? DefaultEncryptTimeout;
                RecryptTimeout = recryptTimeout ?? DefaultRecryptTimeout;
                Options = options ?? new();
                if (Options.Algorithm is null) Options.WithEncryptionAlgorithm();
                EncryptTimer = new()
                {
                    Interval = EncryptTimeout.TotalMilliseconds,
                    AutoReset = false
                };
                EncryptTimer.Elapsed += (s, e) => Encrypt();
                RecryptTimer = new()
                {
                    Interval = RecryptTimeout.TotalMilliseconds,
                    AutoReset = false
                };
                RecryptTimer.Elapsed += (s, e) => Recrypt();
                if (EncryptTimeout == TimeSpan.Zero)
                {
                    Encrypt();
                }
                else
                {
                    EncryptTimer.Start();
                }
            }
            catch (Exception ex)
            {
                Dispose();
                if (ex is CryptographicException) throw;
                throw CryptographicException.From(ex);
            }
            SecureValueTable.Values[GUID] = this;
        }

        /// <summary>
        /// Default encrypt timeout
        /// </summary>
        public static TimeSpan DefaultEncryptTimeout { get; set; } = TimeSpan.FromMilliseconds(150);

        /// <summary>
        /// Default re-crypt timeout
        /// </summary>
        public static TimeSpan DefaultRecryptTimeout { get; set; } = TimeSpan.FromMinutes(1);

        /// <summary>
        /// GUID
        /// </summary>
        public string GUID { get; } = Guid.NewGuid().ToString();

        /// <summary>
        /// Name
        /// </summary>
        public string? Name { get; set; }

        /// <inheritdoc/>
        public IEnumerable<Status> State
        {
            get
            {
                yield return new("GUID", GUID, "Unique ID of the secure value");
                yield return new("Name", Name, "Name of the secure value");
                yield return new("Encrypted", IsEncrypted ? EncryptedSince : false, "If the secure value is encrypted at present (if encrypted, when it has been encrypted)");
                yield return new("Encryption", IsEncrypted ? TimeSpan.Zero : LastAccess + EncryptTimeout, "When the raw value is going to be encrypted next time");
                yield return new("Timeout", EncryptTimeout, "Value encryption timeout after the last access");
                yield return new("Re-crypt", RecryptTimeout, "Encrypted value re-cryption interval");
                yield return new("Access time", LastAccess, "Time of the last raw value access");
                yield return new("Access count", AccessCount, "Number of value access since initialization");
            }
        }

        /// <summary>
        /// Value (should/will be cleared!)
        /// </summary>
        [SensitiveData]
        public byte[] Value
        {
            get
            {
                EnsureUndisposed();
                using SemaphoreSyncContext ssc = Sync;
                LastAccess = DateTime.Now;
                AccessCount++;
                if (RawValue is null) return Decrypt();
                EncryptTimer.Stop();
                try
                {
                    return RawValue.Array.CloneArray();
                }
                finally
                {
                    EncryptTimer.Start();
                    RaiseOnAccess();
                }
            }
            set
            {
                using SecureByteArrayRefStruct secureValue = new(value);
                EnsureUndisposed();
                using SemaphoreSyncContext ssc = Sync;
                RecryptTimer.Stop();
                EncryptTimer.Stop();
                if (RawValue is null)
                {
                    EncryptionKey!.Dispose();
                    EncryptedValue!.Dispose();
                    if (EncryptTimeout == TimeSpan.Zero)
                    {
                        EncryptionKey = new(RND.GetBytes(_KeyLen));
                        EncryptedValue = new(secureValue.Array.Encrypt(EncryptionKey, Options));
                        RecryptTimer.Start();
                        return;
                    }
                    else
                    {
                        EncryptedValue = null;
                        EncryptionKey = null;
                    }
                }
                RawValue?.Dispose();
                RawValue = new(secureValue.Array.CloneArray());
                EncryptTimer.Start();
            }
        }

        /// <summary>
        /// Options
        /// </summary>
        public CryptoOptions Options { get; } = null!;

        /// <summary>
        /// Random value encryption key length in bytes
        /// </summary>
        public int KeyLen
        {
            get => _KeyLen;
            set
            {
                EnsureUndisposed();
                if (_KeyLen == value) return;
                if (value < 1 || value > byte.MaxValue) throw new ArgumentOutOfRangeException(nameof(value));
                _KeyLen = value;
                if (EncryptedValue is not null) Recrypt();
            }
        }

        /// <summary>
        /// Encrypt timeout
        /// </summary>
        public TimeSpan EncryptTimeout { get; }

        /// <summary>
        /// Recrypt timeout
        /// </summary>
        public TimeSpan RecryptTimeout { get; }

        /// <summary>
        /// Is the value encrypted at present?
        /// </summary>
        public bool IsEncrypted => IfUndisposed(() => RawValue is null);

        /// <summary>
        /// Last access time
        /// </summary>
        public DateTime LastAccess { get; private set; } = DateTime.MinValue;

        /// <summary>
        /// Encryption time
        /// </summary>
        public DateTime EncryptedSince { get; private set; } = DateTime.MinValue;

        /// <summary>
        /// Access count
        /// </summary>
        public long AccessCount { get; private set; }

        /// <summary>
        /// Get the value
        /// </summary>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Value (should be cleared!)</returns>
        public async Task<byte[]> GetValueAsync(CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = await Sync.SyncContextAsync(cancellationToken).DynamicContext();
            LastAccess = DateTime.Now;
            AccessCount++;
            if (RawValue is null) return Decrypt();
            EncryptTimer.Stop();
            try
            {
                return RawValue.Array.CloneArray();
            }
            finally
            {
                EncryptTimer.Start();
                RaiseOnAccess();
            }
        }

        /// <summary>
        /// Set the value
        /// </summary>
        /// <param name="value">Value (will be cleared!)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        public async Task SetValueAsync(byte[] value, CancellationToken cancellationToken = default)
        {
            using SecureByteArrayStructSimple secureValue = new(value);
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = await Sync.SyncContextAsync(cancellationToken).DynamicContext();
            RecryptTimer.Stop();
            EncryptTimer.Stop();
            if (RawValue is null)
            {
                EncryptionKey!.Dispose();
                EncryptedValue!.Dispose();
                if (EncryptTimeout == TimeSpan.Zero)
                {
                    EncryptionKey = new(await RND.GetBytesAsync(_KeyLen).DynamicContext());
                    EncryptedValue = new(secureValue.Array.Encrypt(EncryptionKey, Options));
                    RecryptTimer.Start();
                    return;
                }
                else
                {
                    EncryptedValue = null;
                    EncryptionKey = null;
                }
            }
            RawValue?.Dispose();
            RawValue = new(secureValue.Array.CloneArray());
            EncryptTimer.Start();
        }

        /// <summary>
        /// Delegate for an <see cref="OnAccess"/> event handler
        /// </summary>
        /// <param name="value">Secure value</param>
        /// <param name="e">Arguments</param>
        public delegate void Access_Delegate(SecureValue value, EventArgs e);
        /// <summary>
        /// Raised on value access
        /// </summary>
        public event Access_Delegate? OnAccess;
        /// <summary>
        /// Raise the <see cref="OnAccess"/> event
        /// </summary>
        private void RaiseOnAccess()
        {
            if (OnAccess is not null) _ = ((Func<Task>)(async () =>
            {
                await Task.Yield();
                OnAccess?.Invoke(this, new());
            })).StartFairTask();
        }
    }
}
