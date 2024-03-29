﻿using System.ComponentModel.DataAnnotations;
using wan24.Core;
using wan24.ObjectValidation;

namespace wan24.Crypto
{
    /// <summary>
    /// Symmetric key suite (used for PAKE)
    /// </summary>
    public record class SymmetricKeySuite : DisposableRecordBase, ISymmetricKeySuite
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
        /// <param name="identifier">Identifier (will be cleared!)</param>
        /// <param name="expandedKey">Expanded key (will be cleared!)</param>
        public SymmetricKeySuite(in CryptoOptions? options, in byte[]? identifier, in byte[] expandedKey) : this(options)
        {
            Identifier = identifier;
            ExpandedKey = new(expandedKey);
            Options = options ?? Pake.DefaultOptions;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="existing">Existing symmetric key suite (will be cloned)</param>
        /// <param name="options">Options with KDF and MAC settings (will be cleared!)</param>
        public SymmetricKeySuite(in ISymmetricKeySuite existing, in CryptoOptions? options = null) : this(options)
        {
            Identifier = existing.Identifier?.CloneArray();
            ExpandedKey = new(existing.ExpandedKey.Array.CloneArray());
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
        /// <param name="options">Options with KDF and MAC settings (will be cleared!)</param>
        /// <param name="identifier">Identifier (will be cleared!)</param>
        /// <param name="expandedKey">Expanded key (will be cleared!)</param>
        /// <param name="asyncDisposing">Implements asynchronous disposing?</param>
        protected SymmetricKeySuite(in CryptoOptions? options, in byte[]? identifier, in byte[] expandedKey, in bool asyncDisposing) : base(asyncDisposing)
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
        public byte[]? Identifier { get; protected set; }

        /// <inheritdoc/>
        [SensitiveData, NoValidation]
        public SecureByteArray ExpandedKey { get; protected set; }

        /// <summary>
        /// Get a copy of this instance
        /// </summary>
        /// <returns>Instance copy</returns>
        public virtual SymmetricKeySuite GetCopy() => new(Options.GetCopy(), Identifier?.CloneArray(), ExpandedKey.Array.CloneArray());

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
