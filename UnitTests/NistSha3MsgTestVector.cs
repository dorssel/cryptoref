using System.Text.RegularExpressions;
using Dorssel.Security.Cryptography.Reference.FIPS_202.ExtensionMethods;

namespace UnitTests
{
    public partial record NistSha3MsgTestVector(int L, string Msg, string MD);

    public partial record NistSha3MsgTestVector
    {
        public static IReadOnlyList<NistSha3MsgTestVector> All { get; }

        static NistSha3MsgTestVector()
        {
            var testVectors = new List<NistSha3MsgTestVector>();
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
                    testVectors.Add(new(L, Msg, MD));
                }
            }
            All = testVectors.AsReadOnly();
        }
    }
}
