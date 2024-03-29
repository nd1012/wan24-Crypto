﻿namespace wan24.Crypto.Authentication
{
    // PAKE event arguments
    public sealed partial class ServerAuth
    {
        /// <summary>
        /// PAKE event arguments
        /// </summary>
        /// <remarks>
        /// Constructor
        /// </remarks>
        /// <param name="context">Context</param>
        /// <param name="pake">PAKE instance</param>
        /// <param name="pakeServerEventArgs">Pake server event arguments of the original event</param>
        public sealed class PakeEventArgs(ServerAuthContext context, Pake pake, Pake.PakeServerEventArgs pakeServerEventArgs) : EventArgs()
        {
            /// <summary>
            /// Context
            /// </summary>
            public ServerAuthContext Context { get; } = context;

            /// <summary>
            /// PAKE instance
            /// </summary>
            public Pake Pake { get; } = pake;

            /// <summary>
            /// Pake server event arguments of the original event
            /// </summary>
            public Pake.PakeServerEventArgs PakeServerEventArgs { get; } = pakeServerEventArgs;
        }
    }
}
