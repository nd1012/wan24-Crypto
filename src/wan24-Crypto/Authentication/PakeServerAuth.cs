using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto.Authentication
{
    /// <summary>
    /// PAKE authentication server
    /// </summary>
    public sealed partial class PakeServerAuth : DisposableBase
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="options">Options</param>
        public PakeServerAuth(in PakeServerAuthOptions options) : base(asyncDisposing: false)
        {
            try
            {
                Options = options;
                options.PakeOptions ??= Pake.DefaultOptions;
                options.CryptoOptions ??= Pake.DefaultCryptoOptions;
                options.CryptoOptions.LeaveOpen = true;
                Encryption = EncryptionHelper.GetAlgorithm(options.CryptoOptions.Algorithm!);
                if (Encryption.RequireMacAuthentication)
                    throw new ArgumentException("A cipher which requires MAC authentication isn't supported", nameof(options));
                ValueLength = MacHelper.GetAlgorithm(options.PakeOptions.MacAlgorithm!).MacLength;
            }
            catch
            {
                Dispose();
                throw;
            }
        }

        /// <summary>
        /// Options
        /// </summary>
        public PakeServerAuthOptions Options { get; }

        /// <summary>
        /// Encryption algorithm
        /// </summary>
        public EncryptionAlgorithmBase Encryption { get; }

        /// <summary>
        /// PAKE value length in bytes
        /// </summary>
        public int ValueLength { get; }

        /// <summary>
        /// Authenticate
        /// </summary>
        /// <param name="stream">Stream (requires blocking; should be encrypted)</param>
        /// <param name="preSharedSecret">Pre-shared secret (will be cleared!)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>PAKE authentication context (don't forget to dispose!)</returns>
        public async Task<PakeAuthContext> AuthenticateAsync(Stream stream, byte[]? preSharedSecret = null, CancellationToken cancellationToken = default)
        {
            await Task.Yield();
            try
            {
                AuthSequences sequence = (AuthSequences)await stream.ReadOneByteAsync(cancellationToken: cancellationToken).DynamicContext();
                return sequence switch
                {
                    AuthSequences.Authentication => await ProcessAuthenticationAsync(stream, cancellationToken).DynamicContext(),
                    AuthSequences.Signup => await ProcessSignupAsync(stream, preSharedSecret, cancellationToken).DynamicContext(),
                    _ => throw new InvalidDataException($"Invalid received sequence {sequence}"),
                };
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
        /// <returns>If to continue with the signup</returns>
        public delegate Task<bool> SignupValidator_Delegate(PakeServerAuthContext context, CancellationToken cancellationToken);

        /// <summary>
        /// Delegate for a client authentication information factory
        /// </summary>
        /// <param name="context">Context</param>
        /// <param name="serverAuthIdentifier">Authentication server identifier</param>
        /// <param name="cancellationToken">Cancellation token</param>
        public delegate Task ClientAuthFactory_Delegate(PakeServerAuthContext context, ReadOnlyMemory<byte> serverAuthIdentifier, CancellationToken cancellationToken);

        /// <summary>
        /// Delegate for a signup handler
        /// </summary>
        /// <param name="context">Context</param>
        /// <param name="cancellationToken">Cancellation token</param>
        public delegate Task Signup_Delegate(PakeServerAuthContext context, CancellationToken cancellationToken);

        /// <summary>
        /// Delegate for a signup handler
        /// </summary>
        /// <param name="context">Context</param>
        /// <param name="cancellationToken">Cancellation token</param>
        public delegate Task Authentication_Delegate(PakeServerAuthContext context, CancellationToken cancellationToken);

        /// <summary>
        /// Delegate for a PAKE event handler
        /// </summary>
        /// <param name="serverAuth">Server authentication</param>
        /// <param name="e">Arguments</param>
        public delegate void PakeEvent_Delegate(PakeServerAuth serverAuth, PakeEventArgs e);

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
