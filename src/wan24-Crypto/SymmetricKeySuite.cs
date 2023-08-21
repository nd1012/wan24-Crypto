using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Symmetric key suite (manages a 512 bit symmetric key)
    /// </summary>
    public sealed class SymmetricKeySuite : DisposableBase
    {
        /// <summary>
        /// Identifier
        /// </summary>
        private readonly byte[]? _Identifier;
        /// <summary>
        /// Expanded symmetric key
        /// </summary>
        private readonly byte[] _ExpandedKey = null!;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="key">Symmetric key (will be cleared!)</param>
        /// <param name="identifier">Identifier (private!; will be cleared!)</param>
        /// <param name="options">Options (will be cleared!)</param>
        public SymmetricKeySuite(byte[] key, byte[]? identifier = null, CryptoOptions? options = null) : base(asyncDisposing: false)
        {
            try
            {
                if (identifier is not null && (identifier.Length == 0 || identifier.Length > byte.MaxValue)) throw new ArgumentOutOfRangeException(nameof(identifier));
                _Identifier = identifier;
                // Ensure valid options
                Options = options ?? new();
                if (Options.KdfAlgorithm is null) Options.WithKdf();
                if (Options.MacAlgorithm is null) Options.WithMac();
                // Create the expanded key
                if (_Identifier is null)
                {
                    // Without identifier
                    byte[] mac = key.Mac(key, Options);
                    try
                    {
                        _ExpandedKey = key.Stretch(HashSha512Algorithm.HASH_LENGTH, mac, Options).Stretched;
                    }
                    finally
                    {
                        mac.Clear();
                    }
                }
                else
                {
                    // With identifier
                    byte[] keyMac = key.Mac(key, Options),
                        mac = null!;
                    try
                    {
                        mac = _Identifier.Mac(keyMac, Options);
                        _Identifier.Clear();
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
                    _Identifier = mac;
                    _ExpandedKey = key.Stretch(HashSha512Algorithm.HASH_LENGTH, _Identifier, Options).Stretched;
                }
            }
            catch
            {
                Dispose();
                identifier?.Clear();
                key.Clear();
                throw;
            }
        }

        /// <summary>
        /// Options (will be cleared!)
        /// </summary>
        public CryptoOptions Options { get; private set; }

        /// <summary>
        /// Identifier (public; used for identification during authentication; will be cleared!)
        /// </summary>
        public ReadOnlyMemory<byte>? Identifier => _Identifier;

        /// <summary>
        /// Expanded symmetric key (private!; used for en-/decryption and authentication (MAC); is a copy which should be cleared after use!)
        /// </summary>
        public byte[] ExpandedKey => (byte[])_ExpandedKey.Clone();

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            Options.Clear();
            _Identifier?.Clear();
            _ExpandedKey?.Clear();
        }
    }
}
