using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Encrypted value
    /// </summary>
    public class EncryptedValue
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
        public EncryptedValue() { }

        /// <summary>
        /// Options
        /// </summary>
        public CryptoOptions Options { get; set; } = EncryptionHelper.GetDefaultOptions().IncludeNothing().WithMac();

        /// <summary>
        /// Symmetric key
        /// </summary>
        public virtual byte[]? SymmetricKey
        {
            get => _SymmetricKey ??= SymmetricKeyFactory?.Invoke();
            set => _SymmetricKey = value;
        }

        /// <summary>
        /// Symmetric key factory
        /// </summary>
        public Func<byte[]>? SymmetricKeyFactory { get; set; }

        /// <summary>
        /// Asymmetric key
        /// </summary>
        public virtual IAsymmetricPrivateKey? AsymmetricKey
        {
            get => _AsymmetricKey ??= AsymmetricKeyFactory?.Invoke();
            set => _AsymmetricKey = value;
        }

        /// <summary>
        /// Asymmetric key factory
        /// </summary>
        public Func<IAsymmetricPrivateKey>? AsymmetricKeyFactory { get; set; }

        /// <summary>
        /// Has a key?
        /// </summary>
        public bool HasKey => SymmetricKey != null || AsymmetricKey != null;

        /// <summary>
        /// Cipher data
        /// </summary>
        public byte[]? CipherData { get; set; }

        /// <summary>
        /// Store decrypted (once the decrypted raw data was requested)?
        /// </summary>
        public bool StoreDecrypted { get; set; }

        /// <summary>
        /// Raw data
        /// </summary>
        public virtual byte[]? RawData
        {
            get
            {
                if (_Decrypted != null || CipherData == null) return _Decrypted;
                if (!HasKey) throw new InvalidOperationException("No key");
                byte[]? res = SymmetricKey == null
                    ? CipherData.Decrypt(AsymmetricKey!, Options)
                    : CipherData.Decrypt(SymmetricKey, Options);
                if (StoreDecrypted) _Decrypted = res;
                return res;
            }
            set
            {
                if (!HasKey) throw new InvalidOperationException("No key");
                _Decrypted?.Clear();
                _Decrypted = value;
                if (value == null)
                {
                    CipherData = null;
                }
                else
                {
                    CipherData = SymmetricKey == null
                        ? value.Encrypt(AsymmetricKey!, Options)
                        : value.Encrypt(SymmetricKey, Options);
                }
            }
        }
    }
}
