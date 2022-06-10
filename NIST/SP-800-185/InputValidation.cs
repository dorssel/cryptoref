using System.Diagnostics;

namespace Dorssel.Security.Cryptography.Reference.SP_800_185
{
    internal static class InputValidation
    {
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
    }
}
