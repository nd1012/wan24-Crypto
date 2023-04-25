namespace wan24.Crypto
{
    /// <summary>
    /// Event arguments for the <see cref="CryptoHelper.OnForcePostQuantum"/> event
    /// </summary>
    public sealed class ForcePostQuantumEventArgs : EventArgs
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="firstCall">Is the first call?</param>
        /// <param name="strict">Strict post quantum-safety?</param>
        public ForcePostQuantumEventArgs(bool firstCall, bool strict) : base()
        {
            FirstCall = firstCall;
            Strict = strict;
        }

        /// <summary>
        /// Is the first call?
        /// </summary>
        public bool FirstCall { get; }

        /// <summary>
        /// Strict post quantum-safety?
        /// </summary>
        public bool Strict { get; }
    }
}
