namespace wan24.Crypto
{
    /// <summary>
    /// Event arguments for the <see cref="CryptoHelper.OnForcePostQuantum"/> event
    /// </summary>
    /// <remarks>
    /// Constructor
    /// </remarks>
    /// <param name="firstCall">Is the first call?</param>
    /// <param name="strict">Strict post quantum-safety?</param>
    public sealed class ForcePostQuantumEventArgs(bool firstCall, bool strict) : EventArgs()
    {

        /// <summary>
        /// Is the first call?
        /// </summary>
        public bool FirstCall { get; } = firstCall;

        /// <summary>
        /// Strict post quantum-safety?
        /// </summary>
        public bool Strict { get; } = strict;
    }
}
