﻿namespace wan24.Crypto.Networking
{
    // PAKE event arguments
    public sealed partial class ServerAuth
    {
        /// <summary>
        /// PAKE event arguments
        /// </summary>
        public sealed class PakeEventArgs : EventArgs
        {
            /// <summary>
            /// Constructor
            /// </summary>
            /// <param name="context">Context</param>
            /// <param name="pake">PAKE instance</param>
            /// <param name="pakeServerEventArgs">Pake server event arguments of the original event</param>
            public PakeEventArgs(ServerAuthContext context, Pake pake, Pake.PakeServerEventArgs pakeServerEventArgs) : base()
            {
                Context = context;
                Pake = pake;
                PakeServerEventArgs = pakeServerEventArgs;
            }

            /// <summary>
            /// Context
            /// </summary>
            public ServerAuthContext Context { get; }

            /// <summary>
            /// PAKE instance
            /// </summary>
            public Pake Pake { get; }

            /// <summary>
            /// Pake server event arguments of the original event
            /// </summary>
            public Pake.PakeServerEventArgs PakeServerEventArgs { get; }
        }
    }
}