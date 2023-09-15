using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// PAKE
    /// </summary>
    public sealed partial class Pake : DisposableBase
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="options">Options with KDF and MAC settings (will be cleared!)</param>
        public Pake(in CryptoOptions? options = null) : base(asyncDisposing: false)
        {
            Key = null;
            Options = options ?? DefaultOptions.Clone();
            if (Options.KdfAlgorithm is null) Options.WithKdf();
            if (Options.MacAlgorithm is null) Options.WithMac();
            Identity = null;
        }

        /// <summary>
        /// Options with KDF and MAC settings (will be cleared!)
        /// </summary>
        public CryptoOptions Options { get; }

        /// <summary>
        /// Identifier (will be cleared!)
        /// </summary>
        public byte[] Identifier
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get => IfUndisposed(() => Key?.Identifier ?? Identity?.Identifier ?? throw CryptographicException.From(new InvalidOperationException("Unknown identity")));
        }

        /// <summary>
        /// Session key (available after signup/authentication; will be cleared!)
        /// </summary>
        public byte[] SessionKey
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get => IfUndisposed(() => _SessionKey ?? throw CryptographicException.From(new InvalidOperationException("No session key yet")));
        }

        /// <summary>
        /// Determine if this instance contains a session key
        /// </summary>
        [MemberNotNullWhen(returnValue: true, nameof(_SessionKey), nameof(SessionKey))]
        public bool HasSession => IfUndisposed(() => _SessionKey is not null);

        /// <summary>
        /// Clear the session key
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void ClearSessionKey()
        {
            _SessionKey?.Clear();
            _SessionKey = null;
        }
    }
}
