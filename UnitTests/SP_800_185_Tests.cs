using SP_800_185 = Dorssel.Security.Cryptography.Reference.SP_800_185;

namespace UnitTests;

/// <summary>
/// <para>
/// These Known Answer Tests (KATs) are from the
/// <see href="https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program">
/// Cryptographic Algorithm Validation Program CAVP</see>
/// </para>
/// <para>
/// These tests are an informal verification, using the test vectors from
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
public class SP_800_185_Tests
{
    [TestMethod]
    [TestCategory("NIST")]
    [NistKmacSampleDataSource(128)]
    public void KMAC128_Samples(NistKmacSampleTestVector testVector)
    {
        Assert.AreEqual(testVector.Outval, SP_800_185.KMAC.KMAC128(testVector.Key, testVector.Data, testVector.Outval.Length, testVector.S));
    }

    [TestMethod]
    [TestCategory("NIST")]
    [NistKmacSampleDataSource(256)]
    public void KMAC256_Samples(NistKmacSampleTestVector testVector)
    {
        Assert.AreEqual(testVector.Outval, SP_800_185.KMAC.KMAC256(testVector.Key, testVector.Data, testVector.Outval.Length, testVector.S));
    }
}
