using wan24.Compression;
using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto
{
    // Serialization
    public partial record class CryptoOptions
    {
        /// <inheritdoc/>
        protected override void Serialize(Stream stream)
        {
            stream.WriteSerializedNullable(Compression)
                .WriteNumber(MaxUncompressedDataLength)
                .WriteStringNullable(Algorithm)
                .WriteStringNullable(EncryptionOptions)
                .WriteStringNullable(MacAlgorithm)
                .WriteStringNullable(KdfAlgorithm)
                .WriteNumber(KdfIterations)
                .WriteStringNullable(KdfOptions)
                .WriteStringNullable(AsymmetricAlgorithm)
                .WriteStringNullable(AsymmetricAlgorithmOptions)
                .WriteStringNullable(CounterMacAlgorithm)
                .WriteStringNullable(CounterKdfAlgorithm)
                .WriteNumber(CounterKdfIterations)
                .WriteStringNullable(CounterKdfOptions)
                .WriteStringNullable(AsymmetricCounterAlgorithm)
                .WriteStringNullable(HashAlgorithm)
                .WriteNumber(AsymmetricKeyBits)
                .Write(FlagsIncluded)
                .WriteEnum(Flags)
                .WriteEnum(Requirements)
                .WriteNumberNullable(MaximumAge?.TotalMilliseconds)
                .WriteNumberNullable(MaximumTimeOffset?.TotalMilliseconds);
        }

        /// <inheritdoc/>
        protected override async Task SerializeAsync(Stream stream, CancellationToken cancellationToken)
        {
            await stream.WriteSerializedNullableAsync(Compression, cancellationToken).DynamicContext();
            await stream.WriteNumberAsync(MaxUncompressedDataLength, cancellationToken).DynamicContext();
            await stream.WriteStringNullableAsync(Algorithm, cancellationToken).DynamicContext();
            await stream.WriteStringNullableAsync(EncryptionOptions, cancellationToken).DynamicContext();
            await stream.WriteStringNullableAsync(MacAlgorithm, cancellationToken).DynamicContext();
            await stream.WriteStringNullableAsync(KdfAlgorithm, cancellationToken).DynamicContext();
            await stream.WriteNumberAsync(KdfIterations, cancellationToken).DynamicContext();
            await stream.WriteStringNullableAsync(KdfOptions, cancellationToken).DynamicContext();
            await stream.WriteStringNullableAsync(AsymmetricAlgorithm, cancellationToken).DynamicContext();
            await stream.WriteStringNullableAsync(AsymmetricAlgorithmOptions, cancellationToken).DynamicContext();
            await stream.WriteStringNullableAsync(CounterMacAlgorithm, cancellationToken).DynamicContext();
            await stream.WriteStringNullableAsync(CounterKdfAlgorithm, cancellationToken).DynamicContext();
            await stream.WriteNumberAsync(CounterKdfIterations, cancellationToken).DynamicContext();
            await stream.WriteStringNullableAsync(CounterKdfOptions, cancellationToken).DynamicContext();
            await stream.WriteStringNullableAsync(AsymmetricCounterAlgorithm, cancellationToken).DynamicContext();
            await stream.WriteStringNullableAsync(HashAlgorithm, cancellationToken).DynamicContext();
            await stream.WriteNumberAsync(AsymmetricKeyBits, cancellationToken).DynamicContext();
            await stream.WriteAsync(FlagsIncluded, cancellationToken).DynamicContext();
            await stream.WriteEnumAsync(Flags, cancellationToken).DynamicContext();
            await stream.WriteEnumAsync(Requirements, cancellationToken).DynamicContext();
            await stream.WriteNumberNullableAsync(MaximumAge?.TotalMilliseconds, cancellationToken).DynamicContext();
            await stream.WriteNumberNullableAsync(MaximumTimeOffset?.TotalMilliseconds, cancellationToken).DynamicContext();
        }

        /// <inheritdoc/>
        protected override void Deserialize(Stream stream, int version)
        {
            Compression = stream.ReadSerializedNullable<CompressionOptions>(version);
            switch (SerializedObjectVersion ?? VERSION)// Object version switch
            {
                case 2:
                case 3:
                    MaxUncompressedDataLength = stream.ReadNumber<long>(version);
                    break;
            }
            Algorithm = stream.ReadStringNullable(version, minLen: 1, maxLen: byte.MaxValue);
            switch (SerializedObjectVersion ?? VERSION)// Object version switch
            {
                case 3:
                    EncryptionOptions = stream.ReadStringNullable(version, minLen: 2, maxLen: byte.MaxValue);
                    break;
            }
            MacAlgorithm = stream.ReadStringNullable(version, minLen: 1, maxLen: byte.MaxValue);
            KdfAlgorithm = stream.ReadStringNullable(version, minLen: 1, maxLen: byte.MaxValue);
            KdfIterations = stream.ReadNumber<int>(version);
            switch (SerializedObjectVersion ?? VERSION)// Object version switch
            {
                case 3:
                    KdfOptions = stream.ReadStringNullable(version, minLen: 2, maxLen: byte.MaxValue);
                    break;
            }
            AsymmetricAlgorithm = stream.ReadStringNullable(version, minLen: 1, maxLen: byte.MaxValue);
            switch (SerializedObjectVersion ?? VERSION)// Object version switch
            {
                case 3:
                    AsymmetricAlgorithmOptions = stream.ReadStringNullable(version, minLen: 2, maxLen: byte.MaxValue);
                    break;
            }
            CounterMacAlgorithm = stream.ReadStringNullable(version, minLen: 1, maxLen: byte.MaxValue);
            CounterKdfAlgorithm = stream.ReadStringNullable(version, minLen: 1, maxLen: byte.MaxValue);
            CounterKdfIterations = stream.ReadNumber<int>(version);
            switch (SerializedObjectVersion ?? VERSION)// Object version switch
            {
                case 3:
                    CounterKdfOptions = stream.ReadStringNullable(version, minLen: 2, maxLen: byte.MaxValue);
                    break;
            }
            AsymmetricCounterAlgorithm = stream.ReadStringNullable(version, minLen: 1, maxLen: byte.MaxValue);
            HashAlgorithm = stream.ReadStringNullable(version, minLen: 1, maxLen: byte.MaxValue);
            AsymmetricKeyBits = stream.ReadNumber<int>(version);
            FlagsIncluded = stream.ReadBool(version);
            Flags = stream.ReadEnum<CryptoFlags>(version);
            Requirements = stream.ReadEnum<CryptoFlags>(version);
            double? ms = stream.ReadNumberNullable<double>(version);
            if (ms is not null) MaximumAge = TimeSpan.FromMilliseconds(ms.Value);
            ms = stream.ReadNumberNullable<double>(version);
            if (ms is not null) MaximumTimeOffset = TimeSpan.FromMilliseconds(ms.Value);
        }

        /// <inheritdoc/>
        protected override async Task DeserializeAsync(Stream stream, int version, CancellationToken cancellationToken)
        {
            Compression = await stream.ReadSerializedNullableAsync<CompressionOptions>(version, cancellationToken: cancellationToken).DynamicContext();
            switch (SerializedObjectVersion ?? VERSION)// Object version switch
            {
                case 2:
                case 3:
                    MaxUncompressedDataLength = await stream.ReadNumberAsync<long>(version, cancellationToken: cancellationToken).DynamicContext();
                    break;
            }
            Algorithm = await stream.ReadStringNullableAsync(version, minLen: 1, maxLen: byte.MaxValue, cancellationToken: cancellationToken).DynamicContext();
            switch (SerializedObjectVersion ?? VERSION)// Object version switch
            {
                case 3:
                    EncryptionOptions = await stream.ReadStringNullableAsync(version, minLen: 2, maxLen: byte.MaxValue, cancellationToken: cancellationToken).DynamicContext();
                    break;
            }
            MacAlgorithm = await stream.ReadStringNullableAsync(version, minLen: 1, maxLen: byte.MaxValue, cancellationToken: cancellationToken).DynamicContext();
            KdfAlgorithm = await stream.ReadStringNullableAsync(version, minLen: 1, maxLen: byte.MaxValue, cancellationToken: cancellationToken).DynamicContext();
            KdfIterations = await stream.ReadNumberAsync<int>(version, cancellationToken: cancellationToken).DynamicContext();
            switch (SerializedObjectVersion ?? VERSION)// Object version switch
            {
                case 3:
                    KdfOptions = await stream.ReadStringNullableAsync(version, minLen: 2, maxLen: byte.MaxValue, cancellationToken: cancellationToken).DynamicContext();
                    break;
            }
            AsymmetricAlgorithm = await stream.ReadStringNullableAsync(version, minLen: 1, maxLen: byte.MaxValue, cancellationToken: cancellationToken).DynamicContext();
            switch (SerializedObjectVersion ?? VERSION)// Object version switch
            {
                case 3:
                    AsymmetricAlgorithmOptions = await stream.ReadStringNullableAsync(version, minLen: 2, maxLen: byte.MaxValue, cancellationToken: cancellationToken).DynamicContext();
                    break;
            }
            CounterMacAlgorithm = await stream.ReadStringNullableAsync(version, minLen: 1, maxLen: byte.MaxValue, cancellationToken: cancellationToken).DynamicContext();
            CounterKdfAlgorithm = await stream.ReadStringNullableAsync(version, minLen: 1, maxLen: byte.MaxValue, cancellationToken: cancellationToken).DynamicContext();
            CounterKdfIterations = await stream.ReadNumberAsync<int>(version, cancellationToken: cancellationToken).DynamicContext();
            switch (SerializedObjectVersion ?? VERSION)// Object version switch
            {
                case 3:
                    CounterKdfOptions = await stream.ReadStringNullableAsync(version, minLen: 2, maxLen: byte.MaxValue, cancellationToken: cancellationToken).DynamicContext();
                    break;
            }
            AsymmetricCounterAlgorithm = await stream.ReadStringNullableAsync(version, minLen: 1, maxLen: byte.MaxValue, cancellationToken: cancellationToken).DynamicContext();
            HashAlgorithm = await stream.ReadStringNullableAsync(version, minLen: 1, maxLen: byte.MaxValue, cancellationToken: cancellationToken).DynamicContext();
            AsymmetricKeyBits = await stream.ReadNumberAsync<int>(version, cancellationToken: cancellationToken).DynamicContext();
            FlagsIncluded = await stream.ReadBoolAsync(version, cancellationToken: cancellationToken).DynamicContext();
            Flags = await stream.ReadEnumAsync<CryptoFlags>(version, cancellationToken: cancellationToken).DynamicContext();
            Requirements = await stream.ReadEnumAsync<CryptoFlags>(version, cancellationToken: cancellationToken).DynamicContext();
            double? ms = await stream.ReadNumberNullableAsync<double>(version, cancellationToken: cancellationToken).DynamicContext();
            if (ms is not null) MaximumAge = TimeSpan.FromMilliseconds(ms.Value);
            ms = await stream.ReadNumberNullableAsync<double>(version, cancellationToken: cancellationToken).DynamicContext();
            if (ms is not null) MaximumTimeOffset = TimeSpan.FromMilliseconds(ms.Value);
        }
    }
}
