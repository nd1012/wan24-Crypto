using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Symmetric key suite (used for PAKE)
    /// </summary>
    public class SymmetricKeySuite : DisposableBase
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="key">Symmetric key (private!; will be cleared!)</param>
        /// <param name="identifier">Identifier (private!; will be cleared!)</param>
        /// <param name="options">Options with KDF and MAC settings (will be cleared!)</param>
        public SymmetricKeySuite(byte[] key, byte[]? identifier = null, CryptoOptions? options = null) : this(options)
        {
            try
            {
                if (identifier is null)
                {
                    ExpandedKey = new(InitKeyOnly(key));
                }
                else
                {
                    (byte[] expandedKey, Identifier) = InitKeyAndIdentifier(key, identifier);
                    ExpandedKey = new(expandedKey);
                }
            }
            catch(Exception ex)
            {
                Dispose();
                identifier?.Clear();
                key.Clear();
                throw CryptographicException.From("Symmetric key suite initialization failed", ex);
            }
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="options">Options with KDF and MAC settings (will be cleared!)</param>
        /// <param name="asyncDisposing">Implements asynchronous disposing?</param>
        protected SymmetricKeySuite(CryptoOptions? options = null, bool asyncDisposing = false) : base(asyncDisposing)
        {
            Identifier = null!;
            ExpandedKey = null!;
            Options = options ?? Pake.DefaultOptions;
        }

        /// <summary>
        /// Options with KDF and MAC settings (will be cleared!)
        /// </summary>
        public CryptoOptions Options { get; }

        /// <summary>
        /// Identifier (public; used for identification during authentication; will be cleared!)
        /// </summary>
        public byte[]? Identifier { get; }

        /// <summary>
        /// Expanded symmetric key (private!; used for en-/decryption and authentication; will be cleared!)
        /// </summary>
        public SecureByteArray ExpandedKey { get; }

        /// <summary>
        /// Initialize with only having a key
        /// </summary>
        /// <param name="key">Key</param>
        /// <returns>Expanded key</returns>
        protected virtual byte[] InitKeyOnly(byte[] key)
        {
            byte[] mac = key.Mac(key, Options);
            try
            {
                return key.Stretch(mac.Length, mac, Options).Stretched;
            }
            finally
            {
                mac.Clear();
            }
        }

        /// <summary>
        /// Initialize with having a key and an identifier
        /// </summary>
        /// <param name="key">Key</param>
        /// <param name="identifier">Identifier</param>
        /// <returns>Expanded key and identifier</returns>
        protected virtual (byte[] ExpandedKey, byte[] Identifier) InitKeyAndIdentifier(byte[] key, byte[] identifier)
        {
            byte[] keyMac = key.Mac(key, Options),
                mac = null!;
            try
            {
                mac = identifier.Mac(keyMac, Options);
                return (key.Stretch(mac.Length, mac, Options).Stretched, mac);
            }
            catch
            {
                mac?.Clear();
                throw;
            }
            finally
            {
                keyMac.Clear();
            }
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            Options.Clear();
            Identifier?.Clear();
            ExpandedKey?.Dispose();
        }
    }
}
