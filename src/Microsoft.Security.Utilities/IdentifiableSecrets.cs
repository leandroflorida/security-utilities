// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace Microsoft.Security.Utilities
{
    public static class IdentifiableSecrets
    {
        internal static uint MaximumGeneratedKeySize => 4096;
        internal static uint MinimumGeneratedKeySize => 24;

        /// <summary>
        /// Generate an identifiable secret rendered in the standard base64-encoding alphabet.
        /// </summary>
        /// <param name="checksumSeed"></param>
        /// <param name="keyLengthInBytes">The size of the secret.</param>
        /// <param name="base64EncodedSignature">The signature that will be encoded in the identifiable secret.</param>
        /// <param name="encodeForUrl">'true' if the returned token should be encoded in a URL-compatible form 
        /// (replacing the '+' and '/' characters and dropping any padding).</param>
        /// <returns></returns>
        public static string GenerateBase64Key(ulong checksumSeed,
                                               uint keyLengthInBytes,
                                               string base64EncodedSignature,
                                               bool encodeForUrl = false)
        {
            if (keyLengthInBytes > MaximumGeneratedKeySize)
            {
                throw new ArgumentException(
                    "Key length must be less than 4096 bytes.",
                    nameof(keyLengthInBytes));
            }

            if (keyLengthInBytes < MinimumGeneratedKeySize)
            {
                throw new ArgumentException(
                    "Key length must be at least 24 bytes to provide sufficient security (>128 bits of entropy).",
                    nameof(keyLengthInBytes));
            }

            // NOTE: 'identifiable keys' help create security value by encoding signatures in
            //       both the binary and encoded forms of the token. Because of the minimum
            //       key length enforcement immediately above, this code DOES NOT COMPROMISE
            //       THE ACTUAL SECURITY OF THE KEY. The current SDL standard recommends 192
            //       bits of entropy. The minimum threshold is 128 bits.
            //
            //       Encoding signatures both at the binary level and within the base64-encoded
            //       version virtually eliminates false positives and false negatives in
            //       detection and enables for extremely efficient scanning. These values
            //       allow for much more stringent security controls, such as blocking keys
            //       entirely from source code, work items, etc.
            //
            // 'S' == signature byte : 'C' == checksum byte : '?' == sensitive byte
            // ????????????????????????????????????????????????????????????????????????????SSSSCCCCCC==
            // 
            using var cryptoProvider = new RNGCryptoServiceProvider();
            var randomBytes = new byte[keyLengthInBytes];
            cryptoProvider.GetBytes(randomBytes);

            return GenerateKeyWithAppendedSignatureAndChecksum(randomBytes,
                                                               base64EncodedSignature,
                                                               checksumSeed,
                                                               encodeForUrl);
        }

        /// <summary>
        /// Validate if the identifiable secret contains a valid format.
        /// </summary>
        /// <param name="key">A base64-encoded identifiable secret, encoded using the standard base64-alphabet or a URL friendly alternate.</param>
        /// <param name="checksumSeed">The seed used to initialize the Marvin32 checksum algorithm.</param>
        /// <param name="expectedSignature">A fixed signature that should immediately precese the checksum in the encoded secret.</param>
        /// <param name="encodeForUrl">'true' if the secret was encoded for URLs (replacing '+' and '/' characters and eliminating any padding).</param>
        /// <returns></returns>
        public static bool ValidateBase64Key(string key, ulong checksumSeed, string expectedSignature, bool encodeForUrl)
        {
            int keyLength = key.Length;

            if (!key.Contains(expectedSignature))
            {
                return false;
            }

#if NETSTANDARD2_0_OR_GREATER || NET5_0_OR_GREATER
            var bytes = new ReadOnlySpan<byte>(ConvertFromBase64String(key));
            int expectedChecksum = BitConverter.ToInt32(bytes.Slice(bytes.Length - 4, 4).ToArray(), 0);
            int actualChecksum = Marvin.ComputeHash32(bytes.Slice(0, bytes.Length - 4), checksumSeed);
#else
            byte[] bytes = ConvertFromBase64String(key);
            int checksumOffset = bytes.Length - 4;
            var checksumOffsetData = new byte[4];
            var checksumData = new byte[bytes.Length - 4];

            Array.Copy(bytes, checksumOffset, checksumOffsetData, destinationIndex: 0, length: 4);
            int expectedChecksum = BitConverter.ToInt32(checksumOffsetData, 0);

            Array.Copy(bytes, sourceIndex: 0, checksumData, destinationIndex: 0, length: checksumOffset);
            int actualChecksum = Marvin.ComputeHash32(checksumData, checksumSeed, 0, checksumData.Length);
#endif

            if (actualChecksum != expectedChecksum)
            {
                return false;
            }

            // Compute the padding or 'spillover' into the final base64-encoded secret
            // for the random portion of the token, which is our data array minus
            // 7 bytes (3 bytes for the fixed signature, 4 bytes for the checksum).
            int padding = ComputeSpilloverBitsIntoFinalEncodedCharacter(bytes.Length - 7);

            string equalsSigns = string.Empty;
            int equalsSignIndex = key.IndexOf('=');
            int prefixLength = keyLength - 10;
            string pattern = string.Empty;

            if (equalsSignIndex > -1)
            {
                equalsSigns = encodeForUrl ? string.Empty : key.Substring(equalsSignIndex);
                prefixLength = equalsSignIndex - 10;
            }

            string trimmedKey = key.Trim('=');
            char lastChar = trimmedKey[trimmedKey.Length - 1];
            char firstChar = trimmedKey[trimmedKey.Length - 6];

            string specialChars = encodeForUrl ? "\\-_" : "\\/+";
            string secretAlphabet = $"[a-zA-Z0-9{specialChars}]";

            // We need to escape characters in the signature that are special in regex.
            expectedSignature = expectedSignature.Replace("+", "\\+");

            string checksumPrefix = string.Empty, checksumSuffix = string.Empty;

            switch (padding)
            {
                case 2:
                {
                    // When we are required to right-shift the fixed signatures by two
                    // bits, the first encoded character of the checksum will have its
                    // first two bits set to zero, limiting encoded chars to A-P.
                    if (firstChar < 'A' || firstChar > 'P')
                    {
                        return false;
                    }
                    checksumPrefix = "[A-P]";
                    break;
                }

                case 4:
                {
                    // When we are required to right-shift the fixed signatures by four
                    // bits, the first encoded character of the checksum will have its
                    // first four bits set to zero, limiting encoded chars to A-D.
                    if (firstChar < 'A' || firstChar > 'D')
                    {
                        return false;
                    }
                    checksumPrefix = "[A-D]";
                    break;
                }

                default:
                {
                    // In this case, we have a perfect aligment between our decoded
                    // signature and checksum and their encoded representation. As
                    // a result, two bits of the final checksum byte will spill into
                    // the final encoded character, followed by four zeros of padding.
                    // This limits the possible values for the final checksum character
                    // to one of A, Q, g & w.
                    if (lastChar != 'A' && lastChar != 'Q' &&
                        lastChar != 'g' && lastChar != 'w')
                    {
                        return false;
                    }

                    checksumSuffix = "[AQgw]";
                    break;
                }
            }

            // Example patterns, URL-friendly encoding:
            //   [a-zA-Z0-9\-_]{22}XXXX[A-D][a-zA-Z0-9\-_]{5}
            //   [a-zA-Z0-9\-_]{25}XXXX[A-P][a-zA-Z0-9\\-_]{5}
            //   [a-zA-Z0-9\-_]{24}XXXX[a-zA-Z0-9\-_]{5}[AQgw]

            pattern = $"{secretAlphabet}{{{prefixLength}}}{expectedSignature}{checksumPrefix}{secretAlphabet}{{5}}{checksumSuffix}{equalsSigns}";
            var regex = new Regex(pattern);
            return regex.IsMatch(key);
        }

        private static int ComputeSpilloverBitsIntoFinalEncodedCharacter(int countOfBytes)
        {
            // Retrieve padding required to maintain the 6-bit alignment
            // that allows the base64-encoded signature to render.
            // 
            // First we compute the # of bits of total information to encode.
            // Next, using the modulo operator, we determine the number of 
            // 'spillover' bits that will flow into, but not not completely 
            // fill, the final 6-bit encoded value. 
            return countOfBytes * 8 % 6;
        }

        private static string GenerateKeyWithAppendedSignatureAndChecksum(byte[] keyValue,
                                                                          string base64EncodedSignature,
                                                                          ulong checksumSeed,
                                                                          bool encodeForUrl)
        {
            int keyLengthInBytes = keyValue.Length;
            int checksumOffset = keyLengthInBytes - 4;
            int signatureOffset = checksumOffset - 4;

            // Compute a signature that will render consistently when
            // base64-encoded. This potentially requires consuming bits
            // from the byte that precedes the signature (to keep data
            // aligned on a 6-bit boundary, as required by base64).
            byte signaturePrefixByte = keyValue[signatureOffset];
            
            byte[] signatureBytes = GetBase64EncodedSignatureBytes(keyLengthInBytes,
                                                                   base64EncodedSignature,
                                                                   signaturePrefixByte);
            signatureBytes.CopyTo(keyValue, signatureOffset);

            // We will disregard the final four bytes of the randomized input, as 
            // these bytes will be overwritten with the checksum, and therefore
            // aren't relevant to that computation.

#if NETSTANDARD2_0_OR_GREATER || NET5_0_OR_GREATER
            var checksumInput = new ReadOnlySpan<byte>(keyValue).Slice(0, keyValue.Length - 4);

            // Calculate the checksum and store it in the final four bytes.
            int checksum = Marvin.ComputeHash32(checksumInput, checksumSeed);
#else
            byte[] checksumInput = new byte[checksumOffset];
            Array.Copy(keyValue, checksumInput, checksumOffset);

            int checksum = Marvin.ComputeHash32(checksumInput, checksumSeed, 0, checksumInput.Length);
#endif

            byte[] checksumBytes = BitConverter.GetBytes(checksum);
            checksumBytes.CopyTo(keyValue, checksumOffset);

            return ConvertToBase64String(keyValue, encodeForUrl);
        }

        internal static byte[] GetBase64EncodedSignatureBytes(int keyLengthInBytes,
                                                              string base64EncodedSignature,
                                                              byte signaturePrefixByte)
        {
            if (base64EncodedSignature?.Length != 4)
            {
                throw new ArgumentException(
                    "Base64-encoded signature must be 4 characters long.",
                    nameof(base64EncodedSignature));
            }

            byte[] signatureBytes = ConvertFromBase64String(base64EncodedSignature);

            uint signature = (uint)signaturePrefixByte << 24;

            // Compute the padding or 'spillover' into the final base64-encoded secret
            // for the random portion of the token, which is our data array minus
            // 7 bytes (3 bytes for the fixed signature, 4 bytes for the checksum).
            int padding = ComputeSpilloverBitsIntoFinalEncodedCharacter(keyLengthInBytes - 7);

            uint mask = uint.MaxValue;

            switch (padding)
            {
                case 2:
                {
                    // Clear two bits where the signature will be right-shifted
                    // to align on the base64-encoded 6-bit boundary.
                    mask = 0xfcffffff;
                    break;
                }

                case 4:
                {
                    // Clear four bits where the signature will be right-shifted
                    // to remain aligned with base64-encoded 6-bit boundary.
                    mask = 0xf0ffffff;
                    break;
                }
            }

            signature &= mask;

            signature |= (uint)signatureBytes[0] << (16 + padding);
            signature |= (uint)signatureBytes[1] << (8 + padding);
            signature |= (uint)signatureBytes[2] << (0 + padding);

            signatureBytes = BitConverter.GetBytes(signature);

            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(signatureBytes);
            }

            return signatureBytes;
        }

        private static byte[] ConvertFromBase64String(string text)
        {
            text = text.Replace('-', '+');
            text = text.Replace('_', '/');
            return Convert.FromBase64String(text);
        }

        private static string ConvertToBase64String(byte[] data, bool encodeForUrl)
        {
            string text = Convert.ToBase64String(data);

            if (encodeForUrl)
            {
                text = text.Replace('+', '-');
                text = text.Replace('/', '_');
            }
            return text;
        }
    }
}
