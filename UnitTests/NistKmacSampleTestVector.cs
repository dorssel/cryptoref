using System.Text;
using System.Text.RegularExpressions;
using Dorssel.Security.Cryptography.Reference.SP_800_185.ExtensionMethods;

namespace UnitTests
{
    public record NistKmacSampleTestVector
    {
        static string BitStringFromSample(string hexWithWhiteSpace)
        {
            return Convert.FromHexString(Regex.Replace(hexWithWhiteSpace, @"\s+", "")).ToBitString();
        }

        public static IReadOnlyList<NistKmacSampleTestVector> All { get; }

        public int Sample { get; }
        public int SecurityStrength { get; }
        public string Key { get; }
        public string Data { get; }
        public string S { get; }
        public string Outval { get; }

        NistKmacSampleTestVector(int Sample, int SecurityStrength, string Key, string Data, string S, string Outval)
        {
            this.Sample = Sample;
            this.SecurityStrength = SecurityStrength;
            this.Key = BitStringFromSample(Key);
            this.Data = BitStringFromSample(Data);
            this.S = Encoding.ASCII.GetBytes(S).ToBitString();
            this.Outval = BitStringFromSample(Outval);
        }

        static NistKmacSampleTestVector()
        {
            var testVectors = new List<NistKmacSampleTestVector>
            {
                new(1, 128, @"
                        40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F
                        50 51 52 53 54 55 56 57 58 59 5A 5B 5C 5D 5E 5F
                    ", @"
                        00 01 02 03
                    ",
                    "", @"
                        E5 78 0B 0D 3E A6 F7 D3 A4 29 C5 70 6A A4 3A 00
                        FA DB D7 D4 96 28 83 9E 31 87 24 3F 45 6E E1 4E
                    "),

                new(2, 128, @"
                        40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F
                        50 51 52 53 54 55 56 57 58 59 5A 5B 5C 5D 5E 5F
                    ", @"
                        00 01 02 03
                    ",
                    "My Tagged Application", @"
                        3B 1F BA 96 3C D8 B0 B5 9E 8C 1A 6D 71 88 8B 71
                        43 65 1A F8 BA 0A 70 70 C0 97 9E 28 11 32 4A A5
                    "),

                new(3, 128, @"
                        40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F
                        50 51 52 53 54 55 56 57 58 59 5A 5B 5C 5D 5E 5F
                    ", @"
                        00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
                        10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
                        20 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F
                        30 31 32 33 34 35 36 37 38 39 3A 3B 3C 3D 3E 3F
                        40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F
                        50 51 52 53 54 55 56 57 58 59 5A 5B 5C 5D 5E 5F
                        60 61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E 6F
                        70 71 72 73 74 75 76 77 78 79 7A 7B 7C 7D 7E 7F
                        80 81 82 83 84 85 86 87 88 89 8A 8B 8C 8D 8E 8F
                        90 91 92 93 94 95 96 97 98 99 9A 9B 9C 9D 9E 9F
                        A0 A1 A2 A3 A4 A5 A6 A7 A8 A9 AA AB AC AD AE AF
                        B0 B1 B2 B3 B4 B5 B6 B7 B8 B9 BA BB BC BD BE BF
                        C0 C1 C2 C3 C4 C5 C6 C7
                    ",
                    "My Tagged Application", @"
                        1F 5B 4E 6C CA 02 20 9E 0D CB 5C A6 35 B8 9A 15
                        E2 71 EC C7 60 07 1D FD 80 5F AA 38 F9 72 92 30
                    "),

                new(4, 256, @"
                        40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F
                        50 51 52 53 54 55 56 57 58 59 5A 5B 5C 5D 5E 5F
                    ", @"
                        00 01 02 03
                    ",
                    "My Tagged Application", @"
                        20 C5 70 C3 13 46 F7 03 C9 AC 36 C6 1C 03 CB 64
                        C3 97 0D 0C FC 78 7E 9B 79 59 9D 27 3A 68 D2 F7
                        F6 9D 4C C3 DE 9D 10 4A 35 16 89 F2 7C F6 F5 95
                        1F 01 03 F3 3F 4F 24 87 10 24 D9 C2 77 73 A8 DD
                    "),

                new(5, 256, @"
                        40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F
                        50 51 52 53 54 55 56 57 58 59 5A 5B 5C 5D 5E 5F
                    ", @"
                        00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
                        10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
                        20 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F
                        30 31 32 33 34 35 36 37 38 39 3A 3B 3C 3D 3E 3F
                        40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F
                        50 51 52 53 54 55 56 57 58 59 5A 5B 5C 5D 5E 5F
                        60 61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E 6F
                        70 71 72 73 74 75 76 77 78 79 7A 7B 7C 7D 7E 7F
                        80 81 82 83 84 85 86 87 88 89 8A 8B 8C 8D 8E 8F
                        90 91 92 93 94 95 96 97 98 99 9A 9B 9C 9D 9E 9F
                        A0 A1 A2 A3 A4 A5 A6 A7 A8 A9 AA AB AC AD AE AF
                        B0 B1 B2 B3 B4 B5 B6 B7 B8 B9 BA BB BC BD BE BF
                        C0 C1 C2 C3 C4 C5 C6 C7
                    ",
                    "", @"
                        75 35 8C F3 9E 41 49 4E 94 97 07 92 7C EE 0A F2
                        0A 3F F5 53 90 4C 86 B0 8F 21 CC 41 4B CF D6 91
                        58 9D 27 CF 5E 15 36 9C BB FF 8B 9A 4C 2E B1 78
                        00 85 5D 02 35 FF 63 5D A8 25 33 EC 6B 75 9B 69
                    "),

                new(6, 256, @"
                        40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F
                        50 51 52 53 54 55 56 57 58 59 5A 5B 5C 5D 5E 5F
                    ", @"
                        00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
                        10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
                        20 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F
                        30 31 32 33 34 35 36 37 38 39 3A 3B 3C 3D 3E 3F
                        40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F
                        50 51 52 53 54 55 56 57 58 59 5A 5B 5C 5D 5E 5F
                        60 61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E 6F
                        70 71 72 73 74 75 76 77 78 79 7A 7B 7C 7D 7E 7F
                        80 81 82 83 84 85 86 87 88 89 8A 8B 8C 8D 8E 8F
                        90 91 92 93 94 95 96 97 98 99 9A 9B 9C 9D 9E 9F
                        A0 A1 A2 A3 A4 A5 A6 A7 A8 A9 AA AB AC AD AE AF
                        B0 B1 B2 B3 B4 B5 B6 B7 B8 B9 BA BB BC BD BE BF
                        C0 C1 C2 C3 C4 C5 C6 C7
                    ",
                    "My Tagged Application", @"
                        B5 86 18 F7 1F 92 E1 D5 6C 1B 8C 55 DD D7 CD 18
                        8B 97 B4 CA 4D 99 83 1E B2 69 9A 83 7D A2 E4 D9
                        70 FB AC FD E5 00 33 AE A5 85 F1 A2 70 85 10 C3
                        2D 07 88 08 01 BD 18 28 98 FE 47 68 76 FC 89 65
                    "),
            };
            All = testVectors.AsReadOnly();
        }
    }
}
