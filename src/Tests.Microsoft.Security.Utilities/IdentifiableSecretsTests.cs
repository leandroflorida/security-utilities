// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Security.Utilities
{
    [TestClass]
    public class IdentifiableSecretsTests
    {
        // Default values which are consistently consumed by tests for positive cases.
        private const string DefaultSignature = "+Sig";
        private const string DefaultSeedText = "DEFAULT0";
        private readonly static ulong DefaultSeed = BitConverter.ToUInt64(Encoding.ASCII.GetBytes(DefaultSeedText).Reverse().ToArray(), 0);

        private static Random s_random;
        private static double s_randomSeed;

        static IdentifiableSecretsTests()
        {
            s_randomSeed = DateTime.UtcNow.TimeOfDay.TotalMilliseconds;
            s_random = new Random((int)s_randomSeed);
        }

        [TestMethod]
        public void IdentifiableSecrets_GenerateBase64Key_ShouldThrowExceptionWhenLengthIsInvalid()
        {
            ulong seed = DefaultSeed;
            string signature = DefaultSignature;

            foreach (bool encodeForUrl in new[] { true, false })
            {
                Assert.ThrowsException<ArgumentException>(() =>
                    IdentifiableSecrets.GenerateBase64Key(seed,
                                                          keyLengthInBytes: IdentifiableSecrets.MaximumGeneratedKeySize + 1,
                                                          signature,
                                                          encodeForUrl));

                Assert.ThrowsException<ArgumentException>(() =>
                    IdentifiableSecrets.GenerateBase64Key(seed,
                                                          keyLengthInBytes: IdentifiableSecrets.MinimumGeneratedKeySize - 1,
                                                          signature,
                                                          encodeForUrl));

                Assert.ThrowsException<ArgumentException>(() =>
                    IdentifiableSecrets.GenerateBase64Key(seed,
                                                          keyLengthInBytes: 32,
                                                          base64EncodedSignature: null,
                                                          encodeForUrl));

                Assert.ThrowsException<ArgumentException>(() =>
                    IdentifiableSecrets.GenerateBase64Key(seed,
                                                          keyLengthInBytes: 32,
                                                          base64EncodedSignature: "this signature is too long",
                                                          encodeForUrl));
            }
        }

        [TestMethod]
        [Timeout(1000 * 60 * 5)]
        public void IdentifiableSecrets_GenerateBase64Key_Comprehensive()
        {
            Console.WriteLine($"The random values in this test were producing using the seed value: {s_randomSeed}");

            // Timeouts in this test would generally indicate that the secret 
            // generation code isn't reliably producing keys using the complete
            // alphabet.

            var keyLengthInBytesValues = new uint[]
            {
                IdentifiableSecrets.MinimumGeneratedKeySize, IdentifiableSecrets.MinimumGeneratedKeySize + 1,
                IdentifiableSecrets.MinimumGeneratedKeySize + 2, IdentifiableSecrets.MinimumGeneratedKeySize + 3,
                IdentifiableSecrets.MaximumGeneratedKeySize - 3, IdentifiableSecrets.MaximumGeneratedKeySize - 2,
                IdentifiableSecrets.MaximumGeneratedKeySize - 2, IdentifiableSecrets.MaximumGeneratedKeySize - 1,
                29, 30, 31, 32, 33, 34, 35,
                63, 64, 65, 66, 67, 68, 69,
            };

            foreach (bool encodeForUrl in new[] { true, false })
            {
                foreach (uint keyLengthInBytes in keyLengthInBytesValues)
                {
                    foreach (ulong seed in GenerateSeedsTheIncludeAllBits())
                    {
                        foreach (string signature in GenerateSignaturesThatIncludeFullAlphabet(encodeForUrl))
                        {
                            foreach (string secret in GenerateSecretsThatIncludeFullAlphabet(seed,
                                                                                             keyLengthInBytes,
                                                                                             signature,
                                                                                             encodeForUrl))
                            {

                                var isValid = IdentifiableSecrets.ValidateBase64Key(secret, seed, signature, encodeForUrl);
                                Assert.IsTrue(isValid);

                                // Next, we validate that modifying the seed, signature or 
                                // the generated token data itself ensures validation fails.
                                ulong newSeed = ~seed;
                                Assert.AreNotEqual(seed, newSeed);
                                isValid = IdentifiableSecrets.ValidateBase64Key(secret, newSeed, signature, encodeForUrl);
                                Assert.IsFalse(isValid);

                                string newSignature = GetReplacementCharacter(signature[0]) + signature.Substring(1);
                                Assert.AreNotEqual(signature, newSignature);
                                isValid = IdentifiableSecrets.ValidateBase64Key(secret, seed, newSignature, encodeForUrl);
                                Assert.IsFalse(isValid);

                                string newSecret = GetReplacementCharacter(secret[0]) + secret.Substring(1);
                                Assert.AreNotEqual(secret, newSecret);
                                isValid = IdentifiableSecrets.ValidateBase64Key(newSecret, seed, signature, encodeForUrl);
                                Assert.IsFalse(isValid);
                            }
                        }
                    }
                }
            }
        }

        IEnumerable<ulong> GenerateSeedsTheIncludeAllBits()
        {
            ulong bitsObserved = 0;

            while (bitsObserved != ulong.MaxValue)
            {
                uint value1 = (uint)s_random.Next(int.MinValue, int.MaxValue);
                uint value2 = (uint)s_random.Next(int.MinValue, int.MaxValue);

                ulong seed = value1 | (ulong)value2 << 32;
                bitsObserved |= seed;
                yield return seed;
            }
        }

        IEnumerable<string> GenerateSignaturesThatIncludeFullAlphabet(bool encodeForUrl)
        {
            // This yield iterator will continue to generate secrets until all
            // 64 characters of the desired encoding has appeared in at least
            // one secret.

            var alphabet = GetBase64Alphabet(encodeForUrl).ToList();

            while (alphabet.Count > 0)
            {
                string signature = GenerateRandomSignature(encodeForUrl, alphabet);

                foreach (char ch in signature) { alphabet.Remove(ch); }
                yield return signature;
            }
        }

        private string GenerateRandomSignature(bool encodeForUrl, IList<char> alphabet)
        {
            int maxValue = alphabet.Count - 1;
            return string.Concat(alphabet[s_random.Next(0, maxValue)],
                                 alphabet[s_random.Next(0, maxValue)],
                                 alphabet[s_random.Next(0, maxValue)],
                                 alphabet[s_random.Next(0, maxValue)]);
        }

        IEnumerable<string> GenerateSecretsThatIncludeFullAlphabet(ulong seed,
                                                                   uint keyLengthInBytes,
                                                                   string signature,
                                                                   bool encodeForUrl)
        {
            // This yield iterator will continue to generate secrets until all
            // 64 characters of the desired encoding has appeared in at least
            // one secret.

            HashSet<char> alphabet = GetBase64Alphabet(encodeForUrl);

            while (alphabet.Count > 0)
            {
                string secret = IdentifiableSecrets.GenerateBase64Key(seed,
                                                                      keyLengthInBytes,
                                                                      signature,
                                                                      encodeForUrl);

                foreach (char ch in secret) { alphabet.Remove(ch); }
                yield return secret;
            }
        }

        private static HashSet<char> GetBase64Alphabet(bool encodeForUrl)
        {
            var alphabet = new HashSet<char>(new char[] {
                '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
                'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
                'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'});

            if (encodeForUrl)
            {
                alphabet.Add('-');
                alphabet.Add('_');
            }
            else
            {
                alphabet.Add('+');
                alphabet.Add('/');
            }

            return alphabet;
        }

        private string GetReplacementCharacter(char ch)
        {
            // Generate a replacement character that works for all possible
            // generated characters in secrets, whether or not they are encoded
            // with the standard or URL-friendly base64 alphabet.

            if (!Char.IsLetter(ch)) { return "x"; }

            return Char.IsUpper(ch)
                ? ch.ToString().ToLowerInvariant()
                : ch.ToString().ToUpperInvariant();
        }
    }
}
