using System.Buffers.Text;
using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto
{
    // Asynchronous validation
    public static partial class SignedAttributes
    {
        /// <summary>
        /// Validate attributes
        /// </summary>
        /// <param name="id">Key ID</param>
        /// <param name="attributes">Attributes</param>
        /// <param name="throwOnError">Throw an exception on error?</param>
        /// <param name="options">Options</param>
        /// <param name="keyStore">Key owner public key store</param>
        /// <param name="usage">Key usage time</param>
        /// <param name="services">Service provider to use, if <c>httpClient</c> wasn't given for online key validation</param>
        /// <param name="httpClient">http client to use for online key validation (won't be disposed)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>If the attributes are valid</returns>
        public static async Task<bool> ValidateAsync(
            byte[] id,
            IReadOnlyDictionary<string, string> attributes,
            bool throwOnError = true,
            ValidationOptions? options = null,
            PublicKeySuiteStore? keyStore = null,
            DateTime? usage = null,
            IServiceProvider? services = null,
            HttpClient? httpClient = null,
            CancellationToken cancellationToken = default
            )
        {
            options ??= new();
            // Domain
            attributes.TryGetValue(PKI_DOMAIN, out string? domain);
            if (domain is null && ((options.AllowedValidationDomains is not null && options.AllowedValidationDomains.Count > 0) || options.DeniedValidationDomains is not null))
            {
                if (throwOnError) throw new InvalidDataException($"{PKI_DOMAIN} - PKI domain is missing");
                return false;
            }
            if (domain is not null)
            {
                if (options.AllowedValidationDomains is not null && options.AllowedValidationDomains.Count < 1)
                {
                    if (throwOnError) throw new InvalidDataException($"{PKI_DOMAIN} - PKI domain is unexpected");
                    return false;
                }
                if (options.AllowedValidationDomains is not null && !options.AllowedValidationDomains.Any(domain.StartsWith))
                {
                    if (throwOnError) throw new InvalidDataException($"{PKI_DOMAIN} - PKI domain is not allowed");
                    return false;
                }
                if (options.DeniedValidationDomains is not null && options.DeniedValidationDomains.Any(domain.StartsWith))
                {
                    if (throwOnError) throw new InvalidDataException($"{PKI_DOMAIN} - PKI domain is denied");
                    return false;
                }
            }
            // Online key validation API URI
            attributes.TryGetValue(ONLINE_KEY_VALIDATION_API_URI, out string? validationUriString);
            if (
                validationUriString is null &&
                ((options.AllowedKeyValidationApiUris is not null && options.AllowedKeyValidationApiUris.Count > 0) || options.DeniedKeyValidationApiUris is not null || options.OnlineKeyValidation)
                )
            {
                if (throwOnError) throw new InvalidDataException($"{ONLINE_KEY_VALIDATION_API_URI} - Online key validation API URI is missing");
                return false;
            }
            if (validationUriString is not null)
            {
                if (options.AllowedKeyValidationApiUris is not null && options.AllowedKeyValidationApiUris.Count < 1)
                {
                    if (throwOnError) throw new InvalidDataException($"{ONLINE_KEY_VALIDATION_API_URI} - Online key validation API URI is unexpected");
                    return false;
                }
                if (!Uri.TryCreate(validationUriString, UriKind.Absolute, out Uri? validationUri))
                {
                    if (throwOnError) throw new InvalidDataException($"{ONLINE_KEY_VALIDATION_API_URI} - Online key validation API URI is invalid");
                    return false;
                }
                if (options.AllowedKeyValidationApiUris is not null && !options.AllowedKeyValidationApiUris.Any(validationUriString.StartsWith))
                {
                    if (throwOnError) throw new InvalidDataException($"{ONLINE_KEY_VALIDATION_API_URI} - Online key validation API URI is not allowed");
                    return false;
                }
                if (options.DeniedKeyValidationApiUris is not null && options.DeniedKeyValidationApiUris.Any(validationUriString.StartsWith))
                {
                    if (throwOnError) throw new InvalidDataException($"{ONLINE_KEY_VALIDATION_API_URI} - Online key validation API URI is denied");
                    return false;
                }
                if (options.OnlineKeyValidation)
                {
                    HttpClient client = httpClient ?? services?.GetService(typeof(HttpClient)) as HttpClient ?? new();
                    try
                    {
                        using HttpRequestMessage request = new(HttpMethod.Get, validationUriString);
                        using HttpResponseMessage response = await client.SendAsync(request, cancellationToken).DynamicContext();
                        if (!response.IsSuccessStatusCode)
                        {
                            if (throwOnError) throw new InvalidDataException($"{ONLINE_KEY_VALIDATION_API_URI} - Online key validation failed with http status {response.StatusCode}");
                            return false;
                        }
                        using Stream responseBody = await response.Content.ReadAsStreamAsync(cancellationToken).DynamicContext();
                        using RentedArrayStructSimple<byte> buffer = new(len: byte.MaxValue, clean: false);
                        int red = await responseBody.ReadAsync(buffer.Memory, cancellationToken).DynamicContext();
                        if (!long.TryParse(buffer.Span[0..red].ToUtf8String(), out long timeStamp))
                        {
                            if (throwOnError) throw new InvalidDataException($"{ONLINE_KEY_VALIDATION_API_URI} - Online key validation failed with invalid response");
                            return false;
                        }
                        if (timeStamp < 1)
                        {
                            if (throwOnError) throw new InvalidDataException($"{ONLINE_KEY_VALIDATION_API_URI} - Online key validation failed with invalid negative timestamp");
                            return false;
                        }
                        if (timeStamp > 0)
                        {
                            DateTime revokationTime = new(timeStamp, DateTimeKind.Utc);
                            if (revokationTime > DateTime.UtcNow + TimeSpan.FromMinutes(5))
                            {
                                if (throwOnError) throw new InvalidDataException($"{ONLINE_KEY_VALIDATION_API_URI} - Online key validation failed with invalid timestamp in the future");
                                return false;
                            }
                            if (usage.HasValue && usage.Value >= revokationTime)
                            {
                                if (throwOnError)
                                    throw new InvalidDataException($"{ONLINE_KEY_VALIDATION_API_URI} - Online key validation failed with revokation time of {revokationTime} at usage time");
                                return false;
                            }
                            else
                            {
                                if (throwOnError) throw new InvalidDataException($"{ONLINE_KEY_VALIDATION_API_URI} - Online key validation failed with revokation time of {revokationTime}");
                                return false;
                            }
                        }
                    }
                    finally
                    {
                        if (httpClient is null) client.Dispose();
                    }
                }
            }
            // Granted key usages
            attributes.TryGetValue(GRANTED_KEY_USAGES, out string? usages);
            if (usages is null && (options.AllowedUsages.HasValue || options.DeniedUsages.HasValue || options.RequiredUsages.HasValue))
            {
                if (throwOnError) throw new InvalidDataException($"{GRANTED_KEY_USAGES} - Granted key usages are missing");
                return false;
            }
            if (usages is not null)
            {
                if (!int.TryParse(usages, out int usagesValue))
                {
                    if (throwOnError) throw new InvalidDataException($"{GRANTED_KEY_USAGES} - Granted key usages value is invalid");
                    return false;
                }
                AsymmetricAlgorithmUsages usagesEnum = (AsymmetricAlgorithmUsages)usagesValue;
                if (!EnumInfo<AsymmetricAlgorithmUsages>.IsValid(usagesEnum))
                {
                    if (throwOnError) throw new InvalidDataException($"{GRANTED_KEY_USAGES} - Granted key usages are invalid");
                    return false;
                }
                if (options.AllowedUsages.HasValue && !options.AllowedUsages.Value.ContainsAnyFlag(usagesEnum.GetContainedFlags().ToArray()))
                {
                    if (throwOnError) throw new InvalidDataException($"{GRANTED_KEY_USAGES} - Granted key usages are not allowed");
                    return false;
                }
                if (options.DeniedUsages.HasValue && usagesEnum.ContainsAnyFlag(options.DeniedUsages.Value.GetContainedFlags().ToArray()))
                {
                    if (throwOnError) throw new InvalidDataException($"{GRANTED_KEY_USAGES} - Granted key usages are denied");
                    return false;
                }
                if (options.RequiredUsages.HasValue && !usagesEnum.ContainsAllFlags(options.RequiredUsages.Value))
                {
                    if (throwOnError) throw new InvalidDataException($"{GRANTED_KEY_USAGES} - Granted key usages are incomplete (missing required usage grant)");
                    return false;
                }
            }
            // Key exchange key
            if (attributes.TryGetValue(KEY_EXCHANGE_PUBLIC_KEY_IDENTIFIER, out string? kePubKey))
            {
                ReadOnlyMemory<char> kePubKeyChars = kePubKey.AsMemory();
                if (kePubKeyChars.Length >> 1 > HashSha512Algorithm.HASH_LENGTH)
                {
                    if (throwOnError) throw new InvalidDataException($"{KEY_EXCHANGE_PUBLIC_KEY_IDENTIFIER} - Public key exchange key identifier is too long");
                    return false;
                }
                if (!Base64.IsValid(kePubKeyChars.Span))
                {
                    if (throwOnError) throw new InvalidDataException($"{KEY_EXCHANGE_PUBLIC_KEY_IDENTIFIER} - Public key exchange key identifier base64 encoding is invalid");
                    return false;
                }
                int len = Base64.GetMaxDecodedFromUtf8Length(kePubKeyChars.Length);
                if (len != HashSha512Algorithm.HASH_LENGTH)
                {
                    if (throwOnError) throw new InvalidDataException($"{KEY_EXCHANGE_PUBLIC_KEY_IDENTIFIER} - Public key exchange key identifier is invalid");
                    return false;
                }
                byte[] keyId;
                using (RentedArrayStructSimple<byte> buffer = new(len, clean: false))
                {
                    len = kePubKeyChars.Span.GetBase64Bytes(buffer.Span);
                    if (len != HashSha512Algorithm.HASH_LENGTH)
                    {
                        if (throwOnError) throw new InvalidDataException($"{KEY_EXCHANGE_PUBLIC_KEY_IDENTIFIER} - Public key exchange key identifier is invalid");
                        return false;
                    }
                    keyId = buffer.Span[0..len].ToArray();
                }
                if (keyStore is not null && keyStore.GetSuite(keyId) is null)
                {
                    if (throwOnError) throw new InvalidDataException($"{KEY_EXCHANGE_PUBLIC_KEY_IDENTIFIER} - Public key exchange key identifier is invalid");
                    return false;
                }
                else if (options.PKI is not null && await options.PKI.GetKeyAsync(keyId, cancellationToken).DynamicContext() is null)
                {
                    if (throwOnError) throw new InvalidDataException($"{KEY_EXCHANGE_PUBLIC_KEY_IDENTIFIER} - Public key exchange key identifier not found in PKI");
                    return false;
                }
            }
            // Counter key exchange key
            if (attributes.TryGetValue(KEY_EXCHANGE_PUBLIC_COUNTER_KEY_IDENTIFIER, out string? kePubCounterKey))
            {
                if (kePubKey is null)
                {
                    if (throwOnError) throw new InvalidDataException($"{KEY_EXCHANGE_PUBLIC_KEY_IDENTIFIER} - Public key exchange key is missing");
                    return false;
                }
                ReadOnlyMemory<char> kePubKeyChars = kePubCounterKey.AsMemory();
                if (kePubKeyChars.Length >> 1 > HashSha512Algorithm.HASH_LENGTH)
                {
                    if (throwOnError) throw new InvalidDataException($"{KEY_EXCHANGE_PUBLIC_COUNTER_KEY_IDENTIFIER} - Public counter key exchange key identifier is too long");
                    return false;
                }
                if (!Base64.IsValid(kePubKeyChars.Span))
                {
                    if (throwOnError) throw new InvalidDataException($"{KEY_EXCHANGE_PUBLIC_COUNTER_KEY_IDENTIFIER} - Public counter key exchange key identifier base64 encoding is invalid");
                    return false;
                }
                int len = Base64.GetMaxDecodedFromUtf8Length(kePubKeyChars.Length);
                if (len != HashSha512Algorithm.HASH_LENGTH)
                {
                    if (throwOnError) throw new InvalidDataException($"{KEY_EXCHANGE_PUBLIC_COUNTER_KEY_IDENTIFIER} - Public counter key exchange key identifier is invalid");
                    return false;
                }
                byte[] keyId;
                using (RentedArrayStructSimple<byte> buffer = new(len, clean: false))
                {
                    len = kePubKeyChars.Span.GetBase64Bytes(buffer.Span);
                    if (len != HashSha512Algorithm.HASH_LENGTH)
                    {
                        if (throwOnError) throw new InvalidDataException($"{KEY_EXCHANGE_PUBLIC_COUNTER_KEY_IDENTIFIER} - Public counter key exchange key identifier is invalid");
                        return false;
                    }
                    keyId = buffer.Span[0..len].ToArray();
                }
                if (keyStore is not null && keyStore.GetSuite(keyId) is null)
                {
                    if (throwOnError) throw new InvalidDataException($"{KEY_EXCHANGE_PUBLIC_COUNTER_KEY_IDENTIFIER} - Public counter key exchange key identifier is invalid");
                    return false;
                }
                else if (options.PKI is not null && await options.PKI.GetKeyAsync(keyId, cancellationToken).DynamicContext() is null)
                {
                    if (throwOnError) throw new InvalidDataException($"{KEY_EXCHANGE_PUBLIC_COUNTER_KEY_IDENTIFIER} - Public counter key exchange key identifier not found in PKI");
                    return false;
                }
            }
            else if (options.RequireKeyExchangeCounterKey)
            {
                if (throwOnError) throw new InvalidDataException($"{KEY_EXCHANGE_PUBLIC_COUNTER_KEY_IDENTIFIER} - Public counter key exchange key is missing");
                return false;
            }
            // Signature key
            if (attributes.TryGetValue(SIGNATURE_PUBLIC_KEY_IDENTIFIER, out string? sigPubKey))
            {
                ReadOnlyMemory<char> sigPubKeyChars = sigPubKey.AsMemory();
                if (sigPubKeyChars.Length >> 1 > HashSha512Algorithm.HASH_LENGTH)
                {
                    if (throwOnError) throw new InvalidDataException($"{SIGNATURE_PUBLIC_KEY_IDENTIFIER} - Public signature key identifier is too long");
                    return false;
                }
                if (!Base64.IsValid(sigPubKeyChars.Span))
                {
                    if (throwOnError) throw new InvalidDataException($"{SIGNATURE_PUBLIC_KEY_IDENTIFIER} - Public signature key identifier base64 encoding is invalid");
                    return false;
                }
                int len = Base64.GetMaxDecodedFromUtf8Length(sigPubKeyChars.Length);
                if (len != HashSha512Algorithm.HASH_LENGTH)
                {
                    if (throwOnError) throw new InvalidDataException($"{SIGNATURE_PUBLIC_KEY_IDENTIFIER} - Public signature key identifier is invalid");
                    return false;
                }
                byte[] keyId;
                using (RentedArrayStructSimple<byte> buffer = new(len, clean: false))
                {
                    len = sigPubKeyChars.Span.GetBase64Bytes(buffer.Span);
                    if (len != HashSha512Algorithm.HASH_LENGTH)
                    {
                        if (throwOnError) throw new InvalidDataException($"{SIGNATURE_PUBLIC_KEY_IDENTIFIER} - Public signature key identifier is invalid");
                        return false;
                    }
                    keyId = buffer.Span[0..len].ToArray();
                }
                if (keyStore is not null && keyStore.GetSuite(keyId) is null)
                {
                    if (throwOnError) throw new InvalidDataException($"{SIGNATURE_PUBLIC_KEY_IDENTIFIER} - Public signature key identifier is invalid");
                    return false;
                }
                else if (options.PKI is not null && await options.PKI.GetKeyAsync(keyId, cancellationToken).DynamicContext() is null)
                {
                    if (throwOnError) throw new InvalidDataException($"{SIGNATURE_PUBLIC_KEY_IDENTIFIER} - Public signature key identifier not found in PKI");
                    return false;
                }
            }
            // Counter signature key
            if (attributes.TryGetValue(SIGNATURE_PUBLIC_COUNTER_KEY_IDENTIFIER, out string? sigPubCounterKey))
            {
                if (kePubKey is null)
                {
                    if (throwOnError) throw new InvalidDataException($"{SIGNATURE_PUBLIC_KEY_IDENTIFIER} - Public signature key is missing");
                    return false;
                }
                ReadOnlyMemory<char> sigPubKeyChars = sigPubCounterKey.AsMemory();
                if (sigPubKeyChars.Length >> 1 > HashSha512Algorithm.HASH_LENGTH)
                {
                    if (throwOnError) throw new InvalidDataException($"{SIGNATURE_PUBLIC_COUNTER_KEY_IDENTIFIER} - Public counter signature key identifier is too long");
                    return false;
                }
                if (!Base64.IsValid(sigPubKeyChars.Span))
                {
                    if (throwOnError) throw new InvalidDataException($"{SIGNATURE_PUBLIC_COUNTER_KEY_IDENTIFIER} - Public counter signature key identifier base64 encoding is invalid");
                    return false;
                }
                int len = Base64.GetMaxDecodedFromUtf8Length(sigPubKeyChars.Length);
                if (len != HashSha512Algorithm.HASH_LENGTH)
                {
                    if (throwOnError) throw new InvalidDataException($"{SIGNATURE_PUBLIC_COUNTER_KEY_IDENTIFIER} - Public counter signature key identifier is invalid");
                    return false;
                }
                byte[] keyId;
                using (RentedArrayStructSimple<byte> buffer = new(len, clean: false))
                {
                    len = sigPubKeyChars.Span.GetBase64Bytes(buffer.Span);
                    if (len != HashSha512Algorithm.HASH_LENGTH)
                    {
                        if (throwOnError) throw new InvalidDataException($"{SIGNATURE_PUBLIC_COUNTER_KEY_IDENTIFIER} - Public counter signature key identifier is invalid");
                        return false;
                    }
                    keyId = buffer.Span[0..len].ToArray();
                }
                if (keyStore is not null && keyStore.GetSuite(keyId) is null)
                {
                    if (throwOnError) throw new InvalidDataException($"{SIGNATURE_PUBLIC_COUNTER_KEY_IDENTIFIER} - Public counter signature key identifier is invalid");
                    return false;
                }
                else if (options.PKI is not null && await options.PKI.GetKeyAsync(keyId, cancellationToken).DynamicContext() is null)
                {
                    if (throwOnError) throw new InvalidDataException($"{SIGNATURE_PUBLIC_COUNTER_KEY_IDENTIFIER} - Public counter signature key identifier not found in PKI");
                    return false;
                }
            }
            else if (options.RequireSignatureCounterKey)
            {
                if (throwOnError) throw new InvalidDataException($"{SIGNATURE_PUBLIC_COUNTER_KEY_IDENTIFIER} - Public counter signature key is missing");
                return false;
            }
            // Cipher suite
            if (attributes.TryGetValue(CIPHER_SUITE, out string? cipherSuite))
            {
                ReadOnlyMemory<char> cipherSuiteChars = cipherSuite.AsMemory();
                if (!Base64.IsValid(cipherSuiteChars.Span))
                {
                    if (throwOnError) throw new InvalidDataException($"{CIPHER_SUITE} - Cipher suite base64 encoding is invalid");
                    return false;
                }
                int len = Base64.GetMaxDecodedFromUtf8Length(cipherSuiteChars.Length);
                using RentedArrayStructSimple<byte> buffer = new(len, clean: false);
                len = cipherSuiteChars.Span.GetBase64Bytes(buffer.Span);
                using MemoryPoolStream ms = new();
                ms.Write(buffer.Span[0..len]);
                ms.Position = 0;
                CryptoOptions suite;
                try
                {
                    suite = ms.ReadObject<CryptoOptions>();
                }
                catch (Exception ex)
                {
                    if (throwOnError) throw new InvalidDataException($"{CIPHER_SUITE} - Cipher suite deserialization failed: {ex.GetType()}: {ex.Message}");
                    return false;
                }
                try
                {
                    suite.ValidateAlgorithms();
                }
                catch (Exception ex)
                {
                    if (throwOnError) throw new InvalidDataException($"{CIPHER_SUITE} - Cipher suite algorithm validation failed: {ex.Message}");
                    return false;
                }
            }
            else if (options.RequireCipherSuite)
            {
                if (throwOnError) throw new InvalidDataException($"{CIPHER_SUITE} - Cipher suite is missing");
                return false;
            }
            // Serial
            attributes.TryGetValue(SERIAL, out string? serial);
            if (serial is not null)
            {
                if (!int.TryParse(serial, out int serialValue))
                {
                    if (throwOnError) throw new InvalidDataException($"{SERIAL} - Serial is invalid");
                    return false;
                }
                if (keyStore is not null)
                {
                    if (keyStore.GetSuiteByAttribute(SERIAL, serial) is not PublicKeySuite keySuite)
                    {
                        if (throwOnError) throw new InvalidDataException($"{SERIAL} - Serial is unknown");
                        return false;
                    }
                    if (!keySuite.SignedPublicKey!.PublicKey.ID.SlowCompare(id))
                    {
                        if (throwOnError) throw new InvalidDataException($"{SERIAL} - Serial public key ID mismatch");
                        return false;
                    }
                }
                else if (options.PKI is not null && await options.PKI.GetKeyAsync(id, cancellationToken).DynamicContext() is AsymmetricSignedPublicKey pkiKey)
                {
                    if (!pkiKey.Attributes.TryGetValue(SERIAL, out string? pkiSerial))
                    {
                        if (throwOnError) throw new InvalidDataException($"{SERIAL} - Serial is unknown in PKI key");
                        return false;
                    }
                    if (!int.TryParse(serial, out int pkiSerialValue))
                    {
                        if (throwOnError) throw new InvalidDataException($"{SERIAL} - Serial in PKI key is invalid");
                        return false;
                    }
                    if (serialValue != pkiSerialValue)
                    {
                        if (throwOnError) throw new InvalidDataException($"{SERIAL} - Serial in PKI key mismatch ({pkiSerialValue}/{serialValue})");
                        return false;
                    }
                }
            }
            else if (options.RequireSerial)
            {
                if (throwOnError) throw new InvalidDataException($"{SERIAL} - Serial is missing");
                return false;
            }
            // PKI signature permission
            if (options.RequirePkiSignaturePermission && (!attributes.TryGetValue(PKI_SIGNATURE, out string? pkiSig) || !bool.TryParse(pkiSig, out bool pkiSigFlag) || !pkiSigFlag))
            {
                if (throwOnError) throw new InvalidDataException($"{PKI_SIGNATURE} - PKI signature is not permittet");
                return false;
            }
            // Additional validation
            if (AdditionalValidationAsync is not null)
                await AdditionalValidationAsync(id, attributes, throwOnError, options, keyStore, usage, services, httpClient, cancellationToken).DynamicContext();
            return true;
        }
    }
}
