using System.Diagnostics.CodeAnalysis;
using wan24.Core;

namespace wan24.Crypto.Authentication
{
    /// <summary>
    /// PAKE authentication options
    /// </summary>
    public sealed class PakeClientAuthOptions : DisposableBase
    {
        /// <summary>
        /// Default options
        /// </summary>
        private static PakeClientAuthOptions? _DefaultOptions = null;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="login">Login ID (will be cleared!)</param>
        /// <param name="pwd">Login password (will be cleared!)</param>
        /// <param name="preSharedSecret">Pre-shared signup secret (will be cleared!)</param>
        public PakeClientAuthOptions(in byte[] login, in byte[] pwd, in byte[]? preSharedSecret = null) : base(asyncDisposing: false)
        {
            Login = login;
            Password = pwd;
            PreSharedSecret = preSharedSecret;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="login">Login ID (will be cleared!)</param>
        /// <param name="pwd">Login password (will be cleared!)</param>
        /// <param name="peerIdentity">Peer identity (won't be disposed)</param>
        public PakeClientAuthOptions(in byte[] login, in byte[] pwd, in IPakeAuthRecord peerIdentity) : base(asyncDisposing: false)
        {
            Login = login;
            Password = pwd;
            PeerIdentity = peerIdentity;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="symmetricKey">Symmetric key suite (won't be disposed)</param>
        /// <param name="preSharedSecret">Pre-shared signup secret (will be cleared!)</param>
        public PakeClientAuthOptions(in ISymmetricKeySuite symmetricKey, in byte[]? preSharedSecret = null) : base(asyncDisposing: false)
        {
            SymmetricKey = symmetricKey;
            PreSharedSecret = preSharedSecret;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="symmetricKey">Symmetric key suite (won't be disposed)</param>
        /// <param name="peerIdentity">Peer identity (won't be disposed)</param>
        public PakeClientAuthOptions(in ISymmetricKeySuite symmetricKey, in IPakeAuthRecord peerIdentity) : base(asyncDisposing: false)
        {
            SymmetricKey = symmetricKey;
            PeerIdentity = peerIdentity;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="client">Fast PAKE authentication client (won't be disposed)</param>
        /// <param name="peerIdentity">Peer identity (won't be disposed)</param>
        public PakeClientAuthOptions(in FastPakeAuthClient client, in IPakeAuthRecord peerIdentity) : base(asyncDisposing: false)
        {
            FastPakeAuthClient = client;
            PeerIdentity = peerIdentity;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        private PakeClientAuthOptions() : base(asyncDisposing: false) { }

        /// <summary>
        /// Default options (will be cloned for delivery; should/will be disposed!)
        /// </summary>
        public static PakeClientAuthOptions? DefaultOptions
        {
            get => _DefaultOptions?.Clone();
            set
            {
                value?.Dispose();
                _DefaultOptions = value;
            }
        }

        /// <summary>
        /// Login ID (will be cleared!)
        /// </summary>
        [SensitiveData]
        public byte[]? Login { get; private set; }

        /// <summary>
        /// Login password (will be cleared!)
        /// </summary>
        [SensitiveData]
        public byte[]? Password { get; private set; }

        /// <summary>
        /// Pre-shared signup secret (will be cleared!)
        /// </summary>
        [SensitiveData]
        public byte[]? PreSharedSecret { get; private set; }

        /// <summary>
        /// Symmetric key suite (won't be disposed)
        /// </summary>
        public ISymmetricKeySuite? SymmetricKey { get; private set; }

        /// <summary>
        /// Payload (will be cleared!)
        /// </summary>
        [SensitiveData]
        public byte[]? Payload { get; set; }

        /// <summary>
        /// Encrypt the payload?
        /// </summary>
        public bool EncryptPayload { get; set; }

        /// <summary>
        /// Fast PAKE authentication client (won't be disposed)
        /// </summary>
        public FastPakeAuthClient? FastPakeAuthClient { get; private set; }

        /// <summary>
        /// Peer identity (won't be disposed)
        /// </summary>
        public IPakeAuthRecord? PeerIdentity { get; private set; }

        /// <summary>
        /// PAKE options (require KDF and MAC algorithms)
        /// </summary>
        public CryptoOptions? PakeOptions { get; set; }

        /// <summary>
        /// Crypto options (require encryption algorithms; shouldn't use KDF; cipher must not require MAC authentication)
        /// </summary>
        public CryptoOptions? CryptoOptions { get; set; }

        /// <summary>
        /// Session key value encrypt timeout (<see cref="SecureValue"/>)
        /// </summary>
        public TimeSpan? EncryptTimeout { get; set; }

        /// <summary>
        /// Session key value re-crypt timeout (<see cref="SecureValue"/>)
        /// </summary>
        public TimeSpan? RecryptTimeout { get; set; }

        /// <summary>
        /// Options for encrypting the session key value (<see cref="SecureValue"/>)
        /// </summary>
        public CryptoOptions? SessionKeyCryptoOptions { get; set; }

        /// <summary>
        /// Session key KEK length in bytes (<see cref="SecureValue"/>)
        /// </summary>
        public int SessionKeyKekLength { get; set; } = 64;

        /// <summary>
        /// Get the server authentication response? (the server will confirm a successful authentication)
        /// </summary>
        public bool GetAuthenticationResponse { get; set; } = true;

        /// <summary>
        /// Is for signup?
        /// </summary>
        [MemberNotNullWhen(returnValue: false, nameof(PeerIdentity))]
        public bool IsSignup => PeerIdentity is null;

        /// <summary>
        /// Get a clone of this instance
        /// </summary>
        /// <returns>Clone</returns>
        public PakeClientAuthOptions Clone() => new()
        {
            Login = Login?.CloneArray(),
            Password = Password?.CloneArray(),
            PreSharedSecret = PreSharedSecret?.CloneArray(),
            SymmetricKey = SymmetricKey is null
                ? null
                : new SymmetricKeySuite(SymmetricKey, (SymmetricKey as SymmetricKeySuite)?.Options),
            Payload = Payload?.CloneArray(),
            EncryptPayload = EncryptPayload,
            FastPakeAuthClient = FastPakeAuthClient,
            PeerIdentity = PeerIdentity is null ? null : new PakeAuthRecord(PeerIdentity),
            PakeOptions = PakeOptions?.Clone(),
            CryptoOptions = CryptoOptions?.Clone(),
            EncryptTimeout = EncryptTimeout,
            RecryptTimeout = RecryptTimeout,
            SessionKeyCryptoOptions = SessionKeyCryptoOptions?.Clone(),
            SessionKeyKekLength = SessionKeyKekLength,
            GetAuthenticationResponse = GetAuthenticationResponse
        };

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            if(Login is not null) Login?.Clear();
            if(Password is not null) Password?.Clear();
            if (PreSharedSecret is not null) PreSharedSecret?.Clear();
            if (Payload is not null)
            {
                Payload.Clear();
                Payload = null;
            }
        }
    }
}
