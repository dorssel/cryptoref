using System.Diagnostics;

namespace Dorssel.Security.Cryptography.Reference.SP_800_185
{
    internal static class InputValidation
    {
        public static void NonNegative(int i)
        {
            Debug.Assert(i >= 0);
        }

        public static void Assert(bool assertion)
        {
            Debug.Assert(assertion);
        }

        public static void Bit(char bit)
        {
            Debug.Assert((bit == '0') || (bit == '1'));
        }

        public static void BitString(string s)
        {
            foreach (var bit in s)
            {
                Bit(bit);
            }
        }

        public static void BitStringLength(string s, int length)
        {
            Debug.Assert(s.Length == length);
            BitString(s);
        }

        public static void StateMatrix(char[,,] A, int w)
        {
            Debug.Assert(A.Rank == 3);
            Debug.Assert(A.GetLowerBound(0) == 0);
            Debug.Assert(A.GetUpperBound(0) == 4);
            Debug.Assert(A.GetLowerBound(1) == 0);
            Debug.Assert(A.GetUpperBound(1) == 4);
            Debug.Assert(A.GetLowerBound(2) == 0);
            Debug.Assert(A.GetUpperBound(2) == w - 1);

            for (int x = 0; x < 5; ++x)
            {
                for (int y = 0; y < 5; ++y)
                {
                    for (int z = 0; z < w; ++z)
                    {
                        Bit(A[x, y, z]);
                    }
                }
            }
        }
    }
}
