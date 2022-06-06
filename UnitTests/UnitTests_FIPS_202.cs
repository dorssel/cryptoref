using Dorssel.Security.Cryptography.Reference.FIPS_202.ExtensionMethods;
using System.Text.RegularExpressions;
using FIPS_202 = Dorssel.Security.Cryptography.Reference.FIPS_202;

namespace UnitTests;

/// <summary>
/// <para>
/// These tests are from the
/// <see href="https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program">
/// Cryptographic Algorithm Validation Program CAVP</see>
/// </para>
/// <para>
/// These test are an informal verification, using the test vectors from
/// <see href="https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing">
/// CAVP Testing: Secure Hashing</see>
/// </para>
/// <para>
/// These tests are described in
/// <see href="https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha3vs.pdf">
/// The Secure Hash Algorithm 3 Validation System (SHA3VS)</see>, NIST, April 7, 2016.
/// </para>
/// </summary>
[TestClass]
public class UnitTests_FIPS_202
{
    /// <summary>
    /// This class holds all the ShortMsg and LongMsg test vectors for every defined hash length.
    /// </summary>
    sealed class SHA3_BitTestVectors
    {
        record TestVector(int L, string Msg, string MD);

        static readonly List<TestVector> TestVectors = new();

        static SHA3_BitTestVectors()
        {
            var files = Directory.GetFiles("sha-3bittestvectors", "SHA3*Msg.rsp");
            foreach (var file in files)
            {
                var content = File.ReadAllText(file);
                var L = int.Parse(Regex.Matches(content, @"\[L = (\d+)]").Single().Groups[1].Value);
                foreach (Match match in Regex.Matches(content, @"Len = (\d+)\s*Msg = ([0-9a-fA-F]+)\s*MD = ([0-9a-fA-F]+)"))
                {
                    var Len = int.Parse(match.Groups[1].Value);
                    var Msg = Convert.FromHexString(match.Groups[2].Value).ToBitString(Len);
                    var MD = Convert.FromHexString(match.Groups[3].Value).ToBitString(L);
                    TestVectors.Add(new(L, Msg, MD));
                }
            }
        }

        static IEnumerable<object[]> SelectLength(int L)
            => from testVector in TestVectors where testVector.L == L select new object[] { testVector.Msg, testVector.MD };

        public static IEnumerable<object[]> SHA3_224 => SelectLength(224);
        public static IEnumerable<object[]> SHA3_256 => SelectLength(256);
        public static IEnumerable<object[]> SHA3_384 => SelectLength(384);
        public static IEnumerable<object[]> SHA3_512 => SelectLength(512);
    }

    [TestMethod]
    [DynamicData(nameof(SHA3_BitTestVectors.SHA3_224), typeof(SHA3_BitTestVectors))]
    public void SHA3_BitTestVectors_224(string Msg, string MD)
    {
        Assert.AreEqual(MD, FIPS_202.SHA3.SHA3_224(Msg));
    }

    [TestMethod]
    [DynamicData(nameof(SHA3_BitTestVectors.SHA3_256), typeof(SHA3_BitTestVectors))]
    public void SHA3_BitTestVectors_256(string Msg, string MD)
    {
        Assert.AreEqual(MD, FIPS_202.SHA3.SHA3_256(Msg));
    }

    [TestMethod]
    [DynamicData(nameof(SHA3_BitTestVectors.SHA3_384), typeof(SHA3_BitTestVectors))]
    public void SHA3_BitTestVectors_384(string Msg, string MD)
    {
        Assert.AreEqual(MD, FIPS_202.SHA3.SHA3_384(Msg));
    }

    [TestMethod]
    [DynamicData(nameof(SHA3_BitTestVectors.SHA3_512), typeof(SHA3_BitTestVectors))]
    public void SHA3_BitTestVectors_512(string Msg, string MD)
    {
        Assert.AreEqual(MD, FIPS_202.SHA3.SHA3_512(Msg));
    }

    [TestMethod]
    [DataRow(224)]
    [DataRow(256)]
    [DataRow(384)]
    [DataRow(512)]
    public void SHA3_MonteCarlo(int n)
    {
        string Seed;
        var MDexpected = new string[100];
        {
            var content = File.ReadAllText($@"sha-3bittestvectors\SHA3_{L}Monte.rsp");
            var L = int.Parse(Regex.Matches(content, @"\[L = (\d+)]").Single().Groups[1].Value);
            Assert.AreEqual(n, L);
            Seed = Convert.FromHexString(Regex.Matches(content, @"Seed = ([0-9a-fA-F]+)").Single().Groups[1].Value).ToBitString(L);
            foreach (Match match in Regex.Matches(content, @"COUNT = (\d+)\s*MD = ([0-9a-fA-F]+)"))
            {
                var COUNT = int.Parse(match.Groups[1].Value);
                var MD = Convert.FromHexString(match.Groups[2].Value).ToBitString(L);
                MDexpected[COUNT] = MD;
            }
        }

        Func<string, string> SHA3 = n switch
        {
            224 => FIPS_202.SHA3.SHA3_224,
            256 => FIPS_202.SHA3.SHA3_256,
            384 => FIPS_202.SHA3.SHA3_384,
            512 => FIPS_202.SHA3.SHA3_512,
            _ => throw new InternalTestFailureException($"Undefined SHA3 hash length {L}")
        };

        // SHA3VS Section 6.2.3 (Figure 1)
        {
            FIPS_202.InputValidation.BitStringLength(Seed, n);

            var MD = new string[1001];
            var Msg = new string[1001];

            MD[0] = Seed;
            for (int j = 0; j < 100; j++)
            {
                for (int i = 1; i < 1001; i++)
                {
                    Msg[i] = MD[i - 1];
                    MD[i] = SHA3(Msg[i]);
                }
                MD[0] = MD[1000];
                // NOTE: Instead of OUTPUT, we are testing against the expected value.
                Assert.AreEqual(MDexpected[j], MD[0]);
            }
        }
    }
}
