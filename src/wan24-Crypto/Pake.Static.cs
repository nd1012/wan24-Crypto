﻿using System.Runtime.CompilerServices;
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
            get => _DefaultOptions ??= _DefaultOptions = new CryptoOptions()
                .WithKdf()
                .WithMac();
            set => _DefaultOptions = value;
        }

        /// <summary>
        /// Cast as existing session flag
        /// </summary>
        /// <param name="pake"><see cref="Pake"/></param>
        public static implicit operator bool(Pake pake) => pake.HasSession;

        /// <summary>
        /// Cast as session key (should be cleared!)
        /// </summary>
        /// <param name="pake"><see cref="Pake"/></param>
        public static implicit operator byte[](Pake pake) => pake.SessionKey.CloneArray();

        /// <summary>
        /// Get a session key (should be cleared!)
        /// </summary>
        /// <param name="pake"><see cref="Pake"/></param>
        /// <param name="signup"><see cref="PakeSignup"/> (will be disposed!)</param>
        /// <returns>Session key (should be cleared!)</returns>
        public static byte[] operator +(Pake pake, PakeSignup signup)
        {
            pake.HandleSignup(signup);
            return pake;
        }

        /// <summary>
        /// Get a session key (should be cleared!)
        /// </summary>
        /// <param name="pake"><see cref="Pake"/></param>
        /// <param name="auth"><see cref="PakeAuth"/> (will be disposed!)</param>
        /// <returns>Session key (should be cleared!)</returns>
        public static byte[] operator +(Pake pake, PakeAuth auth) => pake.HandleAuth(auth).CloneArray();
    }
}