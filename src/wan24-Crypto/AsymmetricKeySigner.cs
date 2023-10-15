using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto
{
    /// <summary>
    /// Asymmetric key signer
    /// </summary>
    public class AsymmetricKeySigner
    {
        /// <summary>
        /// Signature key
        /// </summary>
        protected readonly PrivateKeySuite SignatureKeys;
        /// <summary>
        /// Clear all signing request attributes before signing?
        /// </summary>
        protected bool ClearRequestAttributes = true;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="signatureKeys">Signature keys (won't be disposed!)</param>
        public AsymmetricKeySigner(PrivateKeySuite signatureKeys)
        {
            if (signatureKeys.SignatureKey is null) throw new ArgumentException("No signature key", nameof(signatureKeys));
            SignatureKeys = signatureKeys;
        }

        /// <summary>
        /// Singleton instance
        /// </summary>
        public static AsymmetricKeySigner? Instance { get; set; }

        /// <summary>
        /// Signature options (won't be cleared)
        /// </summary>
        public CryptoOptions? SignatureOptions{ get; set; }

        /// <summary>
        /// PKI domain name
        /// </summary>
        public string? PkiDomain { get; set; }

        /// <summary>
        /// Key validation URI template (<c>https://pki.yourdomain.com/validate/{id}</c> for example, where <c>{id}</c> will be replaced with the base64 encoded public key ID)
        /// </summary>
        public string? KeyValidationUriTemplate { get; set; }

        /// <summary>
        /// Cipher suite to embed in the signed key attributes (won't be cleared)
        /// </summary>
        public CryptoOptions? CipherSuite { get; set; }

        /// <summary>
        /// Signature purpose
        /// </summary>
        public string? SignaturePurpose { get; set; }

        /// <summary>
        /// PKI for storing the signed keys (won't be disposed)
        /// </summary>
        public SignedPkiStore? PKI { get; set; }

        /// <summary>
        /// Require a key signing request signature of the key owner?
        /// </summary>
        public bool RequireRequestSignature { get; set; }

        /// <summary>
        /// Sign a key signing request
        /// </summary>
        /// <param name="request">Request</param>
        /// <returns>Signed key (will be disposed, if <see cref="PKI"/> is not <see langword="null"/>)</returns>
        public virtual AsymmetricSignedPublicKey SignKey(AsymmetricPublicKeySigningRequest request)
        {
            if(request.Signature is not null)
            {
                request.ValidateRequestSignature();
            }
            else if (RequireRequestSignature)
            {
                throw new InvalidDataException("Missing signature");
            }
            AsymmetricSignedPublicKey res = request.GetAsUnsignedKey();
            try
            {
                if (ClearRequestAttributes) res.Attributes.Clear();
                if (PkiDomain is not null) res.Attributes[SignedAttributes.PKI_DOMAIN] = PkiDomain;
                if (KeyValidationUriTemplate is not null)
                    res.Attributes[SignedAttributes.ONLINE_KEY_VALIDATION_API_URI] = KeyValidationUriTemplate.Parse(new Dictionary<string, string>()
                    {
                        {"id", Convert.ToBase64String(res.PublicKey.ID) }
                    });
                if (CipherSuite is not null) res.Attributes[SignedAttributes.CIPHER_SUITE] = Convert.ToBase64String(CipherSuite.ToBytes());
                res.Sign(
                    SignatureKeys.SignatureKey!, 
                    SignatureKeys.SignedPublicKey, 
                    SignatureKeys.CounterSignatureKey, 
                    SignatureKeys.SignedPublicCounterKey, 
                    SignaturePurpose,
                    SignatureOptions
                    );
                PKI?.AddGrantedKey(res);
                return res;
            }
            catch
            {
                res.Dispose();
                throw;
            }
        }
    }
}
