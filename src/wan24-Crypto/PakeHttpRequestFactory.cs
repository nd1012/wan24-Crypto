using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// PAKE http request factory
    /// </summary>
    public sealed partial class PakeHttpRequestFactory : PakeHttpRequestFactory<PakeRequest.PakeRequestDto>
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="id">ID (will be cleared!)</param>
        /// <param name="key">Key (will be cleared!)</param>
        public PakeHttpRequestFactory(in byte[] id, in byte[] key) : base(id, key) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keySuite">Key suite (will be disposed!)</param>
        public PakeHttpRequestFactory(in ISymmetricKeySuite keySuite) : base(keySuite) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="client">PAKE client (will be disposed!)</param>
        public PakeHttpRequestFactory(in FastPakeAuthClient client) : base(client) { }

        /// <summary>
        /// Default instance
        /// </summary>
        public static PakeHttpRequestFactory? Instance { get; set; }
    }

    /// <summary>
    /// PAKE http request factory
    /// </summary>
    /// <typeparam name="T">Pake request DTO type</typeparam>
    /// <remarks>
    /// Constructor
    /// </remarks>
    /// <param name="client">PAKE client (will be disposed!)</param>
    public partial class PakeHttpRequestFactory<T>(in FastPakeAuthClient client) : DisposableBase(), IPakeHttpRequestFactory where T : PakeRequest.PakeRequestDto
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="id">ID (will be cleared!)</param>
        /// <param name="key">Key (will be cleared!)</param>
        public PakeHttpRequestFactory(in byte[] id, in byte[] key) : this(new SymmetricKeySuite(key, id)) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keySuite">Key suite (will be disposed!)</param>
        public PakeHttpRequestFactory(in ISymmetricKeySuite keySuite) : this(new FastPakeAuthClient(keySuite)) { }

        /// <inheritdoc/>
        public CryptoOptions Options { get; init; } = EncryptionHelper.GetDefaultOptions();
    }
}
