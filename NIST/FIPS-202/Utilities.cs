using System.Diagnostics;

namespace Dorssel.Security.Cryptography.Reference.FIPS_202.ExtensionMethods;

public static class Utilities
{
    public static int Mod(this int x, int modulus)
    {
        // Input validation
        Debug.Assert(modulus > 0);

        // Function
        return (x %= modulus) < 0 ? (x + modulus) : x;
    }

    public static char Dot(this char bit, char otherBit)
    {
        InputValidation.Bit(bit);
        InputValidation.Bit(otherBit);

        // Function
        return ((bit == '1') && (otherBit == '1')) ? '1' : '0';
    }

    public static char Xor(this char bit, char otherBit)
    {
        InputValidation.Bit(bit);
        InputValidation.Bit(otherBit);

        // Function
        return (bit == otherBit) ? '0' : '1';
    }

    public static string Xor(this string s, string otherString)
    {
        InputValidation.BitString(s);
        InputValidation.BitStringLength(otherString, s.Length);

        // Function
        return new(s.Zip(otherString, (bit1, bit2) => bit1.Xor(bit2)).ToArray());
    }

    public static string ToBitString(this byte[] bytes, int Len)
    {
        // Input validation
        Debug.Assert(Len >= 0);
        Debug.Assert(bytes.Length >= (Len + 7) / 8);

        var bits = new char[Len];
        for (int i = 0; i < Len; ++i)
        {
            bits[i] = ((bytes[i / 8] & (1 << (i % 8))) == 0) ? '0' : '1';
        }
        return new(bits);
    }
}
