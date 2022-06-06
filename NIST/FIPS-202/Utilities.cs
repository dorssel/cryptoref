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
        // Input validation
        Debug.Assert((bit == '0') || (bit == '1'));
        Debug.Assert((otherBit == '0') || (otherBit == '1'));

        // Function
        return ((bit == '1') && (otherBit == '1')) ? '1' : '0';
    }

    public static char Xor(this char bit, char otherBit)
    {
        // Input validation
        Debug.Assert((bit == '0') || (bit == '1'));
        Debug.Assert((otherBit == '0') || (otherBit == '1'));

        // Function
        return (bit == otherBit) ? '0' : '1';
    }

    public static string Xor(this string s, string otherString)
    {
        // Input validation
        Debug.Assert(s.Length == otherString.Length);

        // Function
        return new(s.Zip(otherString, (bit1, bit2) => bit1.Xor(bit2)).ToArray());
    }

    public static string ToBitString(this byte[] bytes, int Len)
    {
        Debug.Assert(bytes.Length >= (Len + 7) / 8);

        var bits = new char[Len];
        for (int i = 0; i < Len; ++i)
        {
            bits[i] = ((bytes[i / 8] & (1 << (i % 8))) == 0) ? '0' : '1';
        }
        return new(bits);
    }
}
