using System.ComponentModel.DataAnnotations;
using wan24.Core;
using wan24.ObjectValidation;

namespace wan24.Crypto
{
    /// <summary>
    /// Symmetric key suite (used for PAKE)
    /// </summary>
    public class SymmetricKeySuite : DisposableBase, ISymmetricKeySuite
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="key">Symmetric key (private!; will be cleared!)</param>
        /// <param name="identifier">Identifier (private!; will be cleared!)</param>
        /// <param name="options">Options with KDF and MAC settings (will be cleared!)</param>
        public SymmetricKeySuite(in byte[] key, in byte[]? identifier = null, in CryptoOptions? options = null) : this(options)
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
        protected SymmetricKeySuite(in CryptoOptions? options = null, in bool asyncDisposing = false) : base(asyncDisposing)
        {
            Identifier = null!;
            ExpandedKey = null!;
            Options = options ?? Pake.DefaultOptions;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="options">Options</param>
        /// <param name="identifier">Identifier (will be cleared!)</param>
        /// <param name="expandedKey">Expanded key (will be cleared!)</param>
        /// <param name="asyncDisposing">Implements asynchronous disposing?</param>
        protected SymmetricKeySuite(in CryptoOptions? options, in byte[]? identifier, in byte[] expandedKey, in bool asyncDisposing = false) : base(asyncDisposing)
        {
            Identifier = identifier;
            ExpandedKey = new(expandedKey);
            Options = options ?? Pake.DefaultOptions;
        }

        /// <summary>
        /// Options with KDF and MAC settings (will be cleared!)
        /// </summary>
        public CryptoOptions Options { get; }

        /// <inheritdoc/>
        [Range(HashMd5Algorithm.HASH_LENGTH, HashSha512Algorithm.HASH_LENGTH)]
        public byte[]? Identifier { get; }

        /// <inheritdoc/>
        [SensitiveData, NoValidation]
        public SecureByteArray ExpandedKey { get; }

        /// <summary>
        /// Clone this instance
        /// </summary>
        /// <returns>Cloned instance</returns>
        public virtual SymmetricKeySuite Clone() => new(Options.Clone(), Identifier?.CloneArray(), ExpandedKey.Array.CloneArray());

        /// <summary>
        /// Initialize with only having a key
        /// </summary>
        /// <param name="key">Key</param>
        /// <returns>Expanded key</returns>
        protected virtual byte[] InitKeyOnly(in byte[] key)
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
        protected virtual (byte[] ExpandedKey, byte[] Identifier) InitKeyAndIdentifier(in byte[] key, in byte[] identifier)
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
