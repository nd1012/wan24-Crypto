using System.Diagnostics.CodeAnalysis;
using wan24.Core;

//TODO Encrypt/Re-crypt timeouts

namespace wan24.Crypto.Authentication
{
    /// <summary>
    /// PAKE authentication options
    /// </summary>
    public sealed class PakeClientAuthOptions : DisposableBase
    {
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
        public PakeClientAuthOptions(in byte[] login, in byte[] pwd, in IPakeRecord peerIdentity) : base(asyncDisposing: false)
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
        public PakeClientAuthOptions(in ISymmetricKeySuite symmetricKey, in IPakeRecord peerIdentity) : base(asyncDisposing: false)
        {
            SymmetricKey = symmetricKey;
            PeerIdentity = peerIdentity;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="client">Fast PAKE authentication client (won't be disposed)</param>
        /// <param name="peerIdentity">Peer identity (won't be disposed)</param>
        public PakeClientAuthOptions(in FastPakeAuthClient client, in IPakeRecord peerIdentity) : base(asyncDisposing: false)
        {
            FastPakeAuthClient = client;
            PeerIdentity = peerIdentity;
        }

        /// <summary>
        /// Login ID (will be cleared!)
        /// </summary>
        [SensitiveData]
        public byte[]? Login { get; }

        /// <summary>
        /// Login password (will be cleared!)
        /// </summary>
        [SensitiveData]
        public byte[]? Password { get; }

        /// <summary>
        /// Pre-shared signup secret (will be cleared!)
        /// </summary>
        [SensitiveData]
        public byte[]? PreSharedSecret { get; }

        /// <summary>
        /// Symmetric key suite (won't be disposed)
        /// </summary>
        public ISymmetricKeySuite? SymmetricKey { get; }

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
        public FastPakeAuthClient? FastPakeAuthClient { get; }

        /// <summary>
        /// Fast PAKE authentication server for the peer authentication handling (won't be disposed)
        /// </summary>
        public FastPakeAuthServer? FastPakeAuthServer { get; set; }

        /// <summary>
        /// Peer identity (won't be disposed)
        /// </summary>
        public IPakeRecord? PeerIdentity { get; }

        /// <summary>
        /// PAKE options (require KDF and MAC algorithms)
        /// </summary>
        public CryptoOptions? PakeOptions { get; set; }

        /// <summary>
        /// Crypto options (require encryption algorithms; shouldn't use KDF)
        /// </summary>
        public CryptoOptions? CryptoOptions { get; set; }

        /// <summary>
        /// Is for signup?
        /// </summary>
        [MemberNotNullWhen(returnValue: false, nameof(PeerIdentity))]
        public bool IsSignup => PeerIdentity is null;

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
