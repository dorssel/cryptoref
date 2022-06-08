using Dorssel.Security.Cryptography.Reference.FIPS_202.ExtensionMethods;
using System.Text.RegularExpressions;
using FIPS_202 = Dorssel.Security.Cryptography.Reference.FIPS_202;

namespace UnitTests;

/// <summary>
/// <para>
/// These Known Ansert Tests (KATs) are from the
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
public class FIPS_202_Tests
{
    [TestMethod]
    [TestCategory("NIST")]
    [TestCategory("Slow")]
    [NistSha3MsgDataSource(224)]
    public void SHA3_224_BitTestVectors(string Msg, string MD)
        => Assert.AreEqual(MD, FIPS_202.SHA3.SHA3_224(Msg));

    [TestMethod]
    [TestCategory("NIST")]
    [TestCategory("Slow")]
    [NistSha3MsgDataSource(256)]
    public void SHA3_256_BitTestVectors(string Msg, string MD)
        => Assert.AreEqual(MD, FIPS_202.SHA3.SHA3_256(Msg));

    [TestMethod]
    [TestCategory("NIST")]
    [TestCategory("Slow")]
    [NistSha3MsgDataSource(384)]
    public void SHA3_384_BitTestVectors(string Msg, string MD)
        => Assert.AreEqual(MD, FIPS_202.SHA3.SHA3_384(Msg));

    [TestMethod]
    [TestCategory("NIST")]
    [TestCategory("Slow")]
    [NistSha3MsgDataSource(512)]
    public void SHA3_512_BitTestVectors(string Msg, string MD)
        => Assert.AreEqual(MD, FIPS_202.SHA3.SHA3_512(Msg));

    [TestMethod]
    [TestCategory("NIST")]
    [TestCategory("Slow")]
    [NistShakeMsgDataSource(128)]
    public void SHAKE128_BitTestVectors(string Msg, int Outputlen, string Output)
        => Assert.AreEqual(Output, FIPS_202.SHA3.SHAKE128(Msg, Outputlen));

    [TestMethod]
    [TestCategory("NIST")]
    [TestCategory("Slow")]
    [NistShakeMsgDataSource(256)]
    public void SHAKE256_BitTestVectors(string Msg, int Outputlen, string Output)
        => Assert.AreEqual(Output, FIPS_202.SHA3.SHAKE256(Msg, Outputlen));

    [TestMethod]
    [TestCategory("NIST")]
    [TestCategory("Slow")]
    [DataRow(224)]
    [DataRow(256)]
    [DataRow(384)]
    [DataRow(512)]
    public void SHA3_MonteCarlo(int n)
    {
        // Load Known Answer Test (KAT) results.
        string Seed;
        var MDexpected = new string[100];
        {
            var content = File.ReadAllText($@"sha-3bittestvectors/SHA3_{n}Monte.rsp");
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
            _ => throw new InternalTestFailureException($"Undefined SHA3 hash length {n}")
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

    [TestMethod]
    [NistSha3MsgDataSource(224, QuickTest = true)]
    public void SHA3_224_BitTestVectors_Quick(string Msg, string MD)
        => SHA3_224_BitTestVectors(Msg, MD);

    [TestMethod]
    [NistSha3MsgDataSource(256, QuickTest = true)]
    public void SHA3_256_BitTestVectors_Quick(string Msg, string MD)
        => SHA3_256_BitTestVectors(Msg, MD);

    [TestMethod]
    [NistSha3MsgDataSource(384, QuickTest = true)]
    public void SHA3_384_BitTestVectors_Quick(string Msg, string MD)
        => SHA3_384_BitTestVectors(Msg, MD);

    [TestMethod]
    [NistSha3MsgDataSource(512, QuickTest = true)]
    public void SHA3_512_BitTestVectors_Quick(string Msg, string MD)
        => SHA3_512_BitTestVectors(Msg, MD);

    [TestMethod]
    [NistShakeMsgDataSource(128, QuickTest = true)]
    public void SHAKE128_BitTestVectors_Quick(string Msg, int Outputlen, string Output)
        => SHAKE128_BitTestVectors(Msg, Outputlen, Output);

    [TestMethod]
    [NistShakeMsgDataSource(256, QuickTest = true)]
    public void SHAKE256_BitTestVectors_Quick(string Msg, int Outputlen, string Output)
        => SHAKE256_BitTestVectors(Msg, Outputlen, Output);
}
