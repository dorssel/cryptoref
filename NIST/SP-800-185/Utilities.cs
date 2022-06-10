using System.Diagnostics;

namespace Dorssel.Security.Cryptography.Reference.SP_800_185.ExtensionMethods;

public static class Utilities
{
    public static int Mod(this int x, int modulus)
    {
        // Input validation
        Debug.Assert(modulus > 0);

        // Function
        return (x %= modulus) < 0 ? (x + modulus) : x;
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

    public static string ToBitString(this byte[] bytes)
        => ToBitString(bytes, bytes.Length * 8);

    public static byte[] ToBytes(this string s)
    {
        InputValidation.BitString(s);
        Debug.Assert((s.Length % 8) == 0);

        var bytes = new byte[s.Length / 8];
        for (int i = 0; i < bytes.Length; ++i)
        {
            bytes[i] = 0;
            for (int j = 0; j < 8; ++j)
            {
                if (s[i * 8 + j] == '1')
                {
                    bytes[i] = (byte)(bytes[i] | (1 << j));
                }
            }
        }
        return bytes;
    }
}
