using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Encrypted value
    /// </summary>
    public class EncryptedValue : DisposableBase
    {
        /// <summary>
        /// Decrypted value
        /// </summary>
        protected byte[]? _Decrypted = null;
        /// <summary>
        /// Symmetric key
        /// </summary>
        protected byte[]? _SymmetricKey = null;
        /// <summary>
        /// Aymmetric key
        /// </summary>
        protected IAsymmetricPrivateKey? _AsymmetricKey = null;

        /// <summary>
        /// Constructor
        /// </summary>
        public EncryptedValue() : base(asyncDisposing: false) { }

        /// <summary>
        /// Options
        /// </summary>
        public CryptoOptions Options { get; set; } = EncryptionHelper.GetDefaultOptions().IncludeNothing().WithMac();

        /// <summary>
        /// Symmetric key (won't be cleared!)
        /// </summary>
        [SensitiveData]
        public virtual byte[]? SymmetricKey
        {
            get => StoreKeys ? _SymmetricKey ??= SymmetricKeyFactory?.Invoke() : SymmetricKeyFactory?.Invoke() ?? _SymmetricKey;
            set => _SymmetricKey = value;
        }

        /// <summary>
        /// Symmetric key factory
        /// </summary>
        public Func<byte[]>? SymmetricKeyFactory { get; set; }

        /// <summary>
        /// Asymmetric key (won't be disposed!)
        /// </summary>
        [SensitiveData]
        public virtual IAsymmetricPrivateKey? AsymmetricKey
        {
            get => StoreKeys ? _AsymmetricKey ??= AsymmetricKeyFactory?.Invoke() : AsymmetricKeyFactory?.Invoke() ?? _AsymmetricKey;
            set => _AsymmetricKey = value;
        }

        /// <summary>
        /// Asymmetric key factory
        /// </summary>
        public Func<IAsymmetricPrivateKey>? AsymmetricKeyFactory { get; set; }

        /// <summary>
        /// Store keys from the factory methods?
        /// </summary>
        public bool StoreKeys { get; set; } = true;

        /// <summary>
        /// Has a key?
        /// </summary>
        public bool HasKey => SymmetricKey is not null || SymmetricKeyFactory is not null || AsymmetricKey is not null || AsymmetricKeyFactory is not null;

        /// <summary>
        /// Cipher data
        /// </summary>
        public byte[]? CipherData { get; set; }

        /// <summary>
        /// Store decrypted (once the decrypted raw data was requested)?
        /// </summary>
        public bool StoreDecrypted { get; set; }

        /// <summary>
        /// Raw data (will be cloned for setting/getting; the store will be cleared when disposing)
        /// </summary>
        [SensitiveData]
        public virtual byte[]? RawData
        {
            get
            {
                if (_Decrypted is not null || CipherData is null) return _Decrypted?.CloneArray();
                if (!HasKey) throw new InvalidOperationException("No key");
                byte[]? res = SymmetricKey is null
                    ? CipherData.Decrypt(AsymmetricKey!, Options)
                    : CipherData.Decrypt(SymmetricKey, Options);
                if (StoreDecrypted) _Decrypted = res.CloneArray();
                return res;
            }
            set
            {
                if (!HasKey) throw new InvalidOperationException("No key");
                _Decrypted?.Clear();
                _Decrypted = value?.CloneArray();
                if (value is null)
                {
                    CipherData = null;
                }
                else
                {
                    CipherData = SymmetricKey is null
                        ? value.Encrypt(AsymmetricKey!, Options)
                        : value.Encrypt(SymmetricKey, Options);
                }
            }
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing) => _Decrypted?.Clear();

        /// <summary>
        /// Cast as cipher data
        /// </summary>
        /// <param name="value">Value</param>
        public static implicit operator byte[]?(EncryptedValue value) => value.CipherData;

        /// <summary>
        /// Cast cipher data as encrypted value
        /// </summary>
        /// <param name="cipherData">Cipher data</param>
        public static explicit operator EncryptedValue(byte[] cipherData) => new() { CipherData = cipherData };
    }
}
