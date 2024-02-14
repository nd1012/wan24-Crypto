using wan24.Core;

namespace wan24.Crypto.Authentication
{
    // Default handlers
    public sealed partial class ServerAuth
    {
        /// <summary>
        /// Validates a signup (requires all information to be signed) against the <see cref="CryptoEnvironment.PKI"/> (can be used as <see cref="ServerAuthOptions.SignupValidator"/>, 
        /// for example)
        /// </summary>
        /// <param name="context">Context</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>If to continue with the signup (may throw also)</returns>
        public static Task<bool> ValidateSignupAsync(ServerAuthContext context, CancellationToken cancellationToken)
            => ValidateSignupAsync(context, allowAttributes: false, cancellationToken);

        /// <summary>
        /// Validates a signup (requires all information to be signed) against the <see cref="CryptoEnvironment.PKI"/> (can be used as <see cref="ServerAuthOptions.SignupValidator"/>, 
        /// for example)
        /// </summary>
        /// <param name="context">Context</param>
        /// <param name="allowAttributes">Allow signed public key attributes?</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>If to continue with the signup (may throw also)</returns>
        public static async Task<bool> ValidateSignupAsync(ServerAuthContext context, bool allowAttributes, CancellationToken cancellationToken)
        {
            // PKI and payload required
            if (CryptoEnvironment.PKI is null) throw new InvalidOperationException("No PKI");
            if (context.Payload is null) throw new ArgumentException("No payload", nameof(context));
            if (context.Payload.KeySigningRequest is null)
            {
                await ValidateKeySuiteAsync(context, cancellationToken).DynamicContext();
            }
            else
            {
                // Validate the key signing request
                if (!allowAttributes && context.Payload.KeySigningRequest.Attributes.Count != 0) throw new InvalidDataException("Attributes denied");
                if (CryptoEnvironment.PKI.GetKey(context.Payload.KeySigningRequest.PublicKey.ID) is not null) throw new InvalidDataException("Existing public key");
                // Validate the key signing request signature
                if (context.Payload.KeySigningRequest.Signature is null) throw new InvalidDataException("Signed key signing request required");
                using ISignaturePublicKey signerPublicKey = context.Payload.KeySigningRequest.Signature.SignerPublicKey;
                if (!context.Payload.KeySigningRequest.PublicKey.ID.SlowCompare(signerPublicKey.ID))
                    throw new InvalidDataException("Key request signer mismatch");
                using MemoryPoolStream ms = new(context.Payload.KeySigningRequest.CreateSignedData());
                await context.Payload.KeySigningRequest.Signature.ValidateSignedDataAsync(ms, cancellationToken: cancellationToken).DynamicContext();
            }
            return true;
        }

        /// <summary>
        /// Adds a new signed public key to the <see cref="CryptoEnvironment.PKI"/> (can be used as <see cref="ServerAuthOptions.SignupHandler"/>, for example)
        /// </summary>
        /// <param name="context">Context</param>
        /// <param name="cancellationToken">Cancellation token</param>
        public static async Task UpdatePkiAsync(ServerAuthContext context, CancellationToken cancellationToken)
        {
            // PKI and payload required
            if (CryptoEnvironment.PKI is null) throw new InvalidOperationException("No PKI");
            if (context.Payload is null) throw new ArgumentException("No payload", nameof(context));
            if (context.PublicClientKeys?.SignedPublicKey is null) throw new ArgumentException("No signed public key (suite)", nameof(context));
            if (context.Payload.KeySigningRequest is null) return;
            // Add the signed public key to the PKI
            await CryptoEnvironment.PKI.AddGrantedKeyAsync(context.PublicClientKeys.SignedPublicKey.GetCopy(), cancellationToken).DynamicContext();
        }

        /// <summary>
        /// Validate the public key suite using the <see cref="CryptoEnvironment.PKI"/> (can be used as <see cref="ServerAuthOptions.PayloadHandler"/>, for example)
        /// </summary>
        /// <param name="context">Context</param>
        /// <param name="cancellationToken">Cancellation token</param>
        public static async Task ValidateKeySuiteAsync(ServerAuthContext context, CancellationToken cancellationToken)
        {
            // PKI and payload required
            if (CryptoEnvironment.PKI is null) throw new InvalidOperationException("No PKI");
            if (context.Payload is null) throw new ArgumentException("No payload", nameof(context));
            // Known public key required
            if (context.PublicClientKeys is null) throw new InvalidDataException("No public client key suite");
            if (context.Payload!.KeySigningRequest is not null) return;
            if (context.PublicClientKeys.SignedPublicKey is null) throw new InvalidDataException("No signed public key");
            AsymmetricSignedPublicKey knownKey = await CryptoEnvironment.PKI.GetKeyAsync(context.PublicClientKeys.SignedPublicKey.PublicKey.ID, cancellationToken).DynamicContext() ?? 
                throw new InvalidDataException("Unknown signed public key");
            // Compare the signed keys
            if (!context.PublicClientKeys.SignedPublicKey.CreateSignedData().SlowCompare(knownKey.CreateSignedData())) throw new InvalidDataException("Invalid signed public key");
            // Validate the key suite signature
            if (context.PublicClientKeys.Signature is null) return;
            using ISignaturePublicKey signerPublicKey = context.PublicClientKeys.Signature.SignerPublicKey;
            if (!signerPublicKey.ID.SlowCompare(context.PublicClientKeys.SignedPublicKey.PublicKey.ID)) throw new InvalidDataException("Public key suite signer mismatch");
            using MemoryPoolStream ms = new(context.PublicClientKeys.CreateSignedData());
            await context.PublicClientKeys.Signature.ValidateSignedDataAsync(ms, cancellationToken: cancellationToken).DynamicContext();
        }
    }
}
