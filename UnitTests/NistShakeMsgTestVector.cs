using System.Text.RegularExpressions;
using Dorssel.Security.Cryptography.Reference.FIPS_202.ExtensionMethods;

namespace UnitTests
{
    public partial record NistShakeMsgTestVector(int L, string Msg, int Outputlen, string Output);

    public partial record NistShakeMsgTestVector
    {
        public static IReadOnlyList<NistShakeMsgTestVector> All { get; }

        static NistShakeMsgTestVector()
        {
            var testVectors = new List<NistShakeMsgTestVector>();
            foreach (var file in Directory.GetFiles("shakebittestvectors", "SHAKE*Msg.rsp"))
            {
                var L = int.Parse(Regex.Matches(file, @"SHAKE(\d+)[^\d]*\.rsp").Single().Groups[1].Value);
                var content = File.ReadAllText(file);
                var Outputlen = int.Parse(Regex.Matches(content, @"\[Outputlen = (\d+)]").Single().Groups[1].Value);
                foreach (Match match in Regex.Matches(content, @"Len = (\d+)\s*Msg = ([0-9a-fA-F]+)\s*Output = ([0-9a-fA-F]+)"))
                {
                    var Len = int.Parse(match.Groups[1].Value);
                    var Msg = Convert.FromHexString(match.Groups[2].Value).ToBitString(Len);
                    var Output = Convert.FromHexString(match.Groups[3].Value).ToBitString(Outputlen);
                    testVectors.Add(new(L, Msg, Outputlen, Output));
                }
            }
            foreach (var file in Directory.GetFiles("shakebittestvectors", "SHAKE*VariableOut.rsp"))
            {
                var L = int.Parse(Regex.Matches(file, @"SHAKE(\d+)[^\d]*\.rsp").Single().Groups[1].Value);
                var content = File.ReadAllText(file);
                var InputLength = int.Parse(Regex.Matches(content, @"\[Input Length = (\d+)]").Single().Groups[1].Value);
                foreach (Match match in Regex.Matches(content, @"Outputlen = (\d+)\s*Msg = ([0-9a-fA-F]+)\s*Output = ([0-9a-fA-F]+)"))
                {
                    var Outputlen = int.Parse(match.Groups[1].Value);
                    var Msg = Convert.FromHexString(match.Groups[2].Value).ToBitString(InputLength);
                    var Output = Convert.FromHexString(match.Groups[3].Value).ToBitString(Outputlen);
                    testVectors.Add(new(L, Msg, Outputlen, Output));
                }
            }
            All = testVectors.AsReadOnly();
        }
    }
}
