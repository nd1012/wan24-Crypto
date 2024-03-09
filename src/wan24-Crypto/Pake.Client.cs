using wan24.Core;

namespace wan24.Crypto
{
    // Client
    public sealed partial class Pake
    {
        /// <summary>
        /// Private key
        /// </summary>
        internal readonly ISymmetricKeySuite? Key;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="key">Private key (requires an identifier; initializes client operations; will be disposed!)</param>
        /// <param name="options">Options with KDF and MAC settings (will be cleared!)</param>
        /// <param name="cryptoOptions">Options for encryption (will be cleared!)</param>
        public Pake(in ISymmetricKeySuite key, in CryptoOptions? options = null, in CryptoOptions? cryptoOptions = null) : this(options, cryptoOptions)
        {
            options?.ValidateAlgorithms();
            cryptoOptions?.ValidateAlgorithms();
            if (key.Identifier is null) throw CryptographicException.From(new ArgumentException("Missing identifier", nameof(key)));
            Key = key;
            Identity = null;
        }

        /// <summary>
        /// Create a signup (client)
        /// </summary>
        /// <param name="payload">Payload (max. <see cref="ushort.MaxValue"/> length; will be cleared!)</param>
        /// <returns>Signup (send this to the server and don't forget to dispose!)</returns>
        public PakeSignup CreateSignup(in byte[]? payload = null)
        {
            EnsureUndisposed();
            if (Key?.Identifier is null) throw CryptographicException.From(new InvalidOperationException("Initialized for server operation"));
            byte[] secret = null!,// Needs to be sent to the server for the signup ONLY
                key = null!,
                random = RND.GetBytes(Key.ExpandedKey.Length),
                signatureKey = null!,
                signature = null!;
            try
            {
                key = CreateAuthKey();// MAC
                secret = CreateSecret(key);// MAC
                signatureKey = CreateSignatureKey(key, secret);// KDF
                signature = SignAndCreateSessionKey(signatureKey, key, random, payload ?? [], secret);// MAC
                return new PakeSignup(Key.Identifier.CloneArray(), secret, key, signature, random, payload);
            }
            catch(Exception ex)
            {
                secret?.Clear();
                key?.Clear();
                random.Clear();
                signature?.Clear();
                payload?.Clear();
                if (ex is CryptographicException) throw;
                throw CryptographicException.From(ex);
            }
            finally
            {
                signatureKey?.Clear();
            }
        }

        /// <summary>
        /// Create an authentication (client)
        /// </summary>
        /// <param name="payload">Payload (max. <see cref="ushort.MaxValue"/> length; will be cleared!)</param>
        /// <param name="encryptPayload">Encrypt the payload?</param>
        /// <returns>Authentication (send this to the server and don't forget to dispose!)</returns>
        public PakeAuth CreateAuth(byte[]? payload = null, in bool encryptPayload = false)
        {
            EnsureUndisposed();
            if (Key?.Identifier is null) throw CryptographicException.From(new InvalidOperationException("Initialized for server operation or missing identifier"));
            byte[] secret = null!,
                key = null!,
                random = RND.GetBytes(Key.ExpandedKey.Length),
                randomMac = null!,
                signatureKey = null!,
                signature = null!;
            try
            {
                key = CreateAuthKey();// MAC
                secret = CreateSecret(key);// MAC
                signatureKey = CreateSignatureKey(key, secret);// KDF
                randomMac = random.Mac(signatureKey, Options);
                if (encryptPayload && payload is not null)
                {
                    byte[] temp = payload;
                    try
                    {
                        payload = EncryptPayload(payload, randomMac);
                    }
                    finally
                    {
                        temp.Clear();
                    }
                }
                signature = SignAndCreateSessionKey(signatureKey, key, random, payload ?? [], secret);// MAC
                return new PakeAuth(Key.Identifier.CloneArray(), key.Xor(randomMac), signature, random, payload);
            }
            catch(Exception ex)
            {
                key?.Clear();
                random.Clear();
                signature?.Clear();
                payload?.Clear();
                if (ex is CryptographicException) throw;
                throw CryptographicException.From(ex);
            }
            finally
            {
                randomMac?.Clear();
                secret?.Clear();
                signatureKey?.Clear();
            }
        }
    }
}
