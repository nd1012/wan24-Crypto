using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Base class for an asymmetric public key
    /// </summary>
    public abstract class AsymmetricPublicKeyBase : AsymmetricKeyBase, IAsymmetricPublicKey
    {
        /// <summary>
        /// Key ID
        /// </summary>
        protected byte[]? _ID = null;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="algorithm">Algorithm name</param>
        protected AsymmetricPublicKeyBase(string algorithm) : base(algorithm) { }

        /// <inheritdoc/>
        public override byte[] ID => (byte[])(_ID ??= KeyData.Array.Hash(HashHelper.GetAlgorithm(HashSha512Algorithm.ALGORITHM_NAME).DefaultOptions)).Clone();

        /// <inheritdoc/>
        public abstract IAsymmetricPublicKey GetCopy();

        /// <inheritdoc/>
        public sealed override object Clone() => GetCopy();

        /// <inheritdoc/>
        public virtual bool ValidateSignature(SignatureContainer signature, byte[]? data = null, bool throwOnError = true)
        {
            try
            {
                EnsureUndisposed();
                if (!Algorithm.CanSign) throw new NotSupportedException("This asymmetric algorithm doesn't support signature");
                if (data != null && !signature.ValidateSignedData(data, throwOnError)) return false;
                return ValidateSignatureInt(signature, throwOnError) && (signature.CounterSigner == null || HybridAlgorithmHelper.ValidateCounterSignature(signature));
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }

        /// <inheritdoc/>
        public virtual bool ValidateSignature(SignatureContainer signature, Stream data, bool throwOnError = true)
        {
            try
            {
                EnsureUndisposed();
                if (!Algorithm.CanSign) throw new NotSupportedException("This asymmetric algorithm doesn't support signature");
                if (data != null && !signature.ValidateSignedData(data, throwOnError)) return false;
                return ValidateSignatureInt(signature, throwOnError) && (signature.CounterSigner == null || HybridAlgorithmHelper.ValidateCounterSignature(signature));
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }

        /// <inheritdoc/>
        public virtual async Task<bool> ValidateSignatureAsync(SignatureContainer signature, Stream data, bool throwOnError = true, CancellationToken cancellationToken = default)
        {
            try
            {
                EnsureUndisposed();
                if (!Algorithm.CanSign) throw new NotSupportedException("This asymmetric algorithm doesn't support signature");
                if (data != null && !await signature.ValidateSignedDataAsync(data, throwOnError, cancellationToken).DynamicContext()) return false;
                return ValidateSignatureInt(signature, throwOnError) && (signature.CounterSigner == null || HybridAlgorithmHelper.ValidateCounterSignature(signature));
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }

        /// <inheritdoc/>
        public virtual bool ValidateSignatureRaw(byte[] signature, byte[] signedHash, bool throwOnError = true) => throw new NotImplementedException();

        /// <summary>
        /// Validate a signature which was created using the private key
        /// </summary>
        /// <param name="signature">Signature</param>
        /// <param name="throwOnError">Throw an exception on validation error?</param>
        /// <returns>If the signature is valid</returns>
        protected virtual bool ValidateSignatureInt(SignatureContainer signature, bool throwOnError = true) => throw new NotSupportedException();

        /// <summary>
        /// Cast as serialized data
        /// </summary>
        /// <param name="publicKey">Public key</param>
        public static implicit operator byte[](AsymmetricPublicKeyBase publicKey) => publicKey.Export();
    }
}
