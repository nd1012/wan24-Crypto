using System.Buffers;
using System.Buffers.Text;
using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto
{
    // Validation
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
        /// <returns>If the attributes are valid</returns>
        public static bool Validate(
            in byte[] id,
            in IReadOnlyDictionary<string, string> attributes,
            in bool throwOnError = true,
            ValidationOptions? options = null,
            in PublicKeySuiteStore? keyStore = null
            )
        {
            options ??= new();
            if (options.OnlineKeyValidation) throw new InvalidOperationException("Synchronous online key validation is not supported, but enabled in the given validation options");
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
                ReadOnlySpan<char> kePubKeyChars = kePubKey.AsSpan();
                if (kePubKeyChars.Length >> 1 > HashSha512Algorithm.HASH_LENGTH)
                {
                    if (throwOnError) throw new InvalidDataException($"{KEY_EXCHANGE_PUBLIC_KEY_IDENTIFIER} - Public key exchange key identifier is too long");
                    return false;
                }
                if (!Base64.IsValid(kePubKeyChars))
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
                using (RentedArrayRefStruct<byte> buffer = new(len, clean: false))
                {
                    len = kePubKeyChars.GetBase64Bytes(buffer.Span);
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
                else if (options.PKI is not null && options.PKI.GetKey(keyId) is null)
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
                ReadOnlySpan<char> kePubKeyChars = kePubCounterKey.AsSpan();
                if (kePubKeyChars.Length >> 1 > HashSha512Algorithm.HASH_LENGTH)
                {
                    if (throwOnError) throw new InvalidDataException($"{KEY_EXCHANGE_PUBLIC_COUNTER_KEY_IDENTIFIER} - Public counter key exchange key identifier is too long");
                    return false;
                }
                if (!Base64.IsValid(kePubKeyChars))
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
                using (RentedArrayRefStruct<byte> buffer = new(len, clean: false))
                {
                    len = kePubKeyChars.GetBase64Bytes(buffer.Span);
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
                else if (options.PKI is not null && options.PKI.GetKey(keyId) is null)
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
                ReadOnlySpan<char> sigPubKeyChars = sigPubKey.AsSpan();
                if (sigPubKeyChars.Length >> 1 > HashSha512Algorithm.HASH_LENGTH)
                {
                    if (throwOnError) throw new InvalidDataException($"{SIGNATURE_PUBLIC_KEY_IDENTIFIER} - Public signature key identifier is too long");
                    return false;
                }
                if (!Base64.IsValid(sigPubKeyChars))
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
                using (RentedArrayRefStruct<byte> buffer = new(len, clean: false))
                {
                    len = sigPubKeyChars.GetBase64Bytes(buffer.Span);
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
                else if (options.PKI is not null && options.PKI.GetKey(keyId) is null)
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
                ReadOnlySpan<char> sigPubKeyChars = sigPubCounterKey.AsSpan();
                if (sigPubKeyChars.Length >> 1 > HashSha512Algorithm.HASH_LENGTH)
                {
                    if (throwOnError) throw new InvalidDataException($"{SIGNATURE_PUBLIC_COUNTER_KEY_IDENTIFIER} - Public counter signature key identifier is too long");
                    return false;
                }
                if (!Base64.IsValid(sigPubKeyChars))
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
                using (RentedArrayRefStruct<byte> buffer = new(len, clean: false))
                {
                    len = sigPubKeyChars.GetBase64Bytes(buffer.Span);
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
                else if (options.PKI is not null && options.PKI.GetKey(keyId) is null)
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
                ReadOnlySpan<char> cipherSuiteChars = cipherSuite.AsSpan();
                if (!Base64.IsValid(cipherSuiteChars))
                {
                    if (throwOnError) throw new InvalidDataException($"{CIPHER_SUITE} - Cipher suite base64 encoding is invalid");
                    return false;
                }
                int len = Base64.GetMaxDecodedFromUtf8Length(cipherSuiteChars.Length);
                using RentedArrayRefStruct<byte> buffer = new(len, clean: false);
                len = cipherSuiteChars.GetBase64Bytes(buffer.Span);
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
                else if (options.PKI?.GetKey(id) is AsymmetricSignedPublicKey pkiKey)
                {
                    if(!pkiKey.Attributes.TryGetValue(SERIAL, out string? pkiSerial))
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
            AdditionalValidation?.Invoke(id, attributes, throwOnError, options, keyStore);
            return true;
        }
    }
}
