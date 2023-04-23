namespace wan24.Crypto
{
    /// <summary>
    /// Interface for an asymmetric public key
    /// </summary>
    public interface IAsymmetricPublicKey : IAsymmetricKey
    {
        /// <summary>
        /// Get a copy
        /// </summary>
        /// <returns>Copy</returns>
        IAsymmetricPublicKey GetCopy();
        /// <summary>
        /// Validate a signature which was created using the private key
        /// </summary>
        /// <param name="signature">Signature</param>
        /// <param name="data">Signed raw data</param>
        /// <param name="throwOnError">Throw an exception on validation error?</param>
        /// <returns>If the signature is valid</returns>
        bool ValidateSignature(SignatureContainer signature, byte[]? data = null, bool throwOnError = true);
        /// <summary>
        /// Validate a signature which was created using the private key
        /// </summary>
        /// <param name="signature">Signature</param>
        /// <param name="data">Signed raw data</param>
        /// <param name="throwOnError">Throw an exception on validation error?</param>
        /// <returns>If the signature is valid</returns>
        bool ValidateSignature(SignatureContainer signature, Stream data, bool throwOnError = true);
        /// <summary>
        /// Validate a signature which was created using the private key
        /// </summary>
        /// <param name="signature">Signature</param>
        /// <param name="data">Signed raw data</param>
        /// <param name="throwOnError">Throw an exception on validation error?</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>If the signature is valid</returns>
        Task<bool> ValidateSignatureAsync(SignatureContainer signature, Stream data, bool throwOnError = true, CancellationToken cancellationToken = default);
        /// <summary>
        /// Validate a raw signature (RFC 3279 DER sequence)
        /// </summary>
        /// <param name="signature">Signature (RFC 3279 DER sequence)</param>
        /// <param name="signedHash">Signed hash</param>
        /// <param name="throwOnError">Throw an exception on validation error?</param>
        /// <returns>If the signature is valid</returns>
        bool ValidateSignatureRaw(byte[] signature, byte[] signedHash, bool throwOnError = true);
    }
}
