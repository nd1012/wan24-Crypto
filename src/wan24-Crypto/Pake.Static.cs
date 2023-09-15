using System.Runtime.CompilerServices;
using wan24.Core;

namespace wan24.Crypto
{
    // Static
    public sealed partial class Pake
    {
        /// <summary>
        /// Default options
        /// </summary>
        private static CryptoOptions? _DefaultOptions = null;

        /// <summary>
        /// Default options
        /// </summary>
        public static CryptoOptions DefaultOptions
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get => _DefaultOptions ??= new CryptoOptions()
                .WithKdf()
                .WithMac();
            set
            {
                _DefaultOptions?.Clear();
                _DefaultOptions = value;
                if (value is null) return;
                if (_DefaultOptions.KdfAlgorithm is null) _DefaultOptions.WithKdf();
                if (_DefaultOptions.MacAlgorithm is null) _DefaultOptions.WithMac();
            }
        }

        /// <summary>
        /// Cast as existing session flag
        /// </summary>
        /// <param name="pake"><see cref="Pake"/></param>
        public static implicit operator bool(in Pake pake) => pake.HasSession;

        /// <summary>
        /// Cast as session key (should be cleared!)
        /// </summary>
        /// <param name="pake"><see cref="Pake"/></param>
        public static implicit operator byte[](in Pake pake) => pake.SessionKey.CloneArray();

        /// <summary>
        /// Get the payload
        /// </summary>
        /// <param name="pake"><see cref="Pake"/></param>
        /// <param name="signup"><see cref="PakeSignup"/> (will be disposed!)</param>
        /// <returns>Payload</returns>
        public static byte[] operator +(in Pake pake, in PakeSignup signup)
        {
            pake.HandleSignup(signup);
            return pake;
        }

        /// <summary>
        /// Get the payload
        /// </summary>
        /// <param name="pake"><see cref="Pake"/></param>
        /// <param name="auth"><see cref="PakeAuth"/> (will be disposed!)</param>
        /// <returns>Payload</returns>
        public static byte[] operator +(in Pake pake, in PakeAuth auth) => pake.HandleAuth(auth).CloneArray();
    }
}
