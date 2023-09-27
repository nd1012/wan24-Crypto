using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto.Networking
{
    /// <summary>
    /// Server authentication
    /// </summary>
    public sealed partial class ServerAuth : DisposableBase
    {
        /// <summary>
        /// Public key signature purpose
        /// </summary>
        public const string PUBLIC_KEY_SIGNATURE_PURPOSE = "Client authentication public signature key";

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="options">Options</param>
        public ServerAuth(in ServerAuthOptions options) : base(asyncDisposing: false)
        {
            Options = options;
            try
            {
                if (options.PrivateKeys.KeyExchangeKey is null) throw new ArgumentException("Missing key exchange key", nameof(options));
                if (options.PrivateKeys.SignatureKey is null) throw new ArgumentException("Missing signature key", nameof(options));
                if (options.AllowAuthentication || options.AllowSignup)
                {
                    if (options.SignClientPublicKey && options.PrivateKeys.SignedPublicKey is null)
                        throw new ArgumentException("Missing signed public key", nameof(options));
                    if (options.IdentityFactory is null) throw new ArgumentException("Missing identity factory", nameof(options));
                    options.HashOptions ??= HashHelper.GetDefaultOptions();
                    options.HashOptions.ApplyPrivateKeySuite(options.PrivateKeys, forSignature: true);
                    options.HashOptions.LeaveOpen = true;
                    options.PakeOptions ??= Pake.DefaultOptions;
                    options.CryptoOptions ??= Pake.DefaultCryptoOptions;
                    options.CryptoOptions.LeaveOpen = true;
                    Encryption = EncryptionHelper.GetAlgorithm(options.CryptoOptions.Algorithm!);
                    if (options.PfsKeyPool is not null)
                    {
                        if (options.PfsKeyPool.Algorithm.Value != options.PrivateKeys.KeyExchangeKey.Algorithm.Value)
                            throw new ArgumentException("PFS key pool algorithm mismatch", nameof(options));
                        if (options.PfsKeyPool.Options.AsymmetricKeyBits != options.PrivateKeys.KeyExchangeKey.Bits)
                            throw new ArgumentException("PFS key pool key size mismatch", nameof(options));
                        if (options.PrivateKeys.CounterKeyExchangeKey is not null)
                        {
                            if (options.PfsCounterKeyPool is null) throw new ArgumentException("Missing PFS counter key pool", nameof(options));
                            if (options.PfsCounterKeyPool.Algorithm.Value != options.PrivateKeys.CounterKeyExchangeKey.Algorithm.Value)
                                throw new ArgumentException("PFS key pool algorithm mismatch", nameof(options));
                            if (options.PfsCounterKeyPool.Options.AsymmetricKeyBits != options.PrivateKeys.CounterKeyExchangeKey.Bits)
                                throw new ArgumentException("PFS key pool key size mismatch", nameof(options));
                        }
                    }
                }
            }
            catch
            {
                Dispose();
                throw;
            }
        }

        /// <summary>
        /// Server authentication options
        /// </summary>
        public ServerAuthOptions Options { get; }

        /// <summary>
        /// Encryption algorithm
        /// </summary>
        public EncryptionAlgorithmBase? Encryption { get; }

        /// <summary>
        /// Authenticate
        /// </summary>
        /// <param name="stream">Stream</param>
        /// <param name="preSharedSecret">Pre-shared secret (will be cleared!)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Client authentication context (don't forget to dispose!)</returns>
        public async Task<ClientAuthContext> AuthenticateAsync(Stream stream, byte[]? preSharedSecret = null, CancellationToken cancellationToken = default)
        {
            await Task.Yield();
            try
            {
                AuthSequences sequence;
                bool publicKeysRequested = false;
                for (cancellationToken.ThrowIfCancellationRequested(); ; cancellationToken.ThrowIfCancellationRequested())
                {
                    sequence = (AuthSequences)await stream.ReadOneByteAsync(cancellationToken: cancellationToken).DynamicContext();
                    switch (sequence)
                    {
                        case AuthSequences.Authentication:
                            if (!Options.AllowAuthentication) throw new UnauthorizedAccessException("Authentication denied");
                            return await ProcessAuthenticationAsync(stream, cancellationToken).DynamicContext();
                        case AuthSequences.Signup:
                            if (!Options.AllowSignup) throw new UnauthorizedAccessException("Signup denied");
                            return await ProcessSignupAsync(stream, preSharedSecret, cancellationToken).DynamicContext();
                        case AuthSequences.PublicKeyRequest:
                            if (!Options.AllowPublicKeyRequest) throw new UnauthorizedAccessException("Server public key request denied");
                            if (publicKeysRequested) throw new UnauthorizedAccessException("Repeated server public key request denied");
                            await ProcessPublicKeyRequestAsync(stream, cancellationToken).DynamicContext();
                            publicKeysRequested = true;
                            break;
                        default:
                            throw new InvalidDataException($"Invalid received sequence {sequence}");
                    }
                }
            }
            catch (Exception ex)
            {
                if (ex is not OperationCanceledException ocEx || ocEx.CancellationToken != cancellationToken)
                    try
                    {
                        await stream.WriteAsync((byte)AuthSequences.Error, cancellationToken).DynamicContext();
                    }
                    catch (Exception ex2)
                    {
                        throw new AggregateException(ex, ex2);
                    }
                throw;
            }
            finally
            {
                preSharedSecret?.Clear();
            }
        }

        /// <summary>
        /// Delegate for a signup validator
        /// </summary>
        /// <param name="context">Context</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>If to continue with the signup (may throw also)</returns>
        public delegate Task<bool> SignupValidator_Delegate(ServerAuthContext context, CancellationToken cancellationToken);

        /// <summary>
        /// Delegate for a identity factory (needs to set <see cref="ServerAuthContext.Identity"/> and <see cref="ServerAuthContext.PublicClientKeys"/>)
        /// </summary>
        /// <param name="context">Context</param>
        /// <param name="cancellationToken">Cancellation token</param>
        public delegate Task Identity_Delegate(ServerAuthContext context, CancellationToken cancellationToken);

        /// <summary>
        /// Delegate for a payload handler
        /// </summary>
        /// <param name="context">Context</param>
        /// <param name="cancellationToken">Cancellation token</param>
        public delegate Task Payload_Delegate(ServerAuthContext context, CancellationToken cancellationToken);

        /// <summary>
        /// Delegate for a signup handler
        /// </summary>
        /// <param name="context">Context</param>
        /// <param name="cancellationToken">Cancellation token</param>
        public delegate Task Signup_Delegate(ServerAuthContext context, CancellationToken cancellationToken);

        /// <summary>
        /// Delegate for a authentication handler
        /// </summary>
        /// <param name="context">Context</param>
        /// <param name="cancellationToken">Cancellation token</param>
        public delegate Task Authentication_Delegate(ServerAuthContext context, CancellationToken cancellationToken);

        /// <summary>
        /// Delegate for a PAKE event handler
        /// </summary>
        /// <param name="serverAuth">Server authentication</param>
        /// <param name="e">Arguments</param>
        public delegate void PakeEvent_Delegate(ServerAuth serverAuth, PakeEventArgs e);

        /// <summary>
        /// Raised on PAKE signup (forwards the <see cref="Pake.OnSignup"/> event)
        /// </summary>
        public event PakeEvent_Delegate? OnPakeSignup;

        /// <summary>
        /// Raised on PAKE authentication (forwards the <see cref="Pake.OnAuth"/> event)
        /// </summary>
        public event PakeEvent_Delegate? OnPakeAuth;

        /// <summary>
        /// Raised on PAKE authentication error (forwards the <see cref="Pake.OnAuthError"/> event)
        /// </summary>
        public event PakeEvent_Delegate? OnPakeAuthError;
    }
}
