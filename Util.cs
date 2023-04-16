using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading;

namespace DSTUSign
{
    internal static class Util
    {

        public static string ByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }
   


 
        public static string ToBinaryString(this BigInteger bigint)
        {
            var bytes = bigint.ToByteArray();
            var idx = bytes.Length - 1;

            // Create a StringBuilder having appropriate capacity.
            var base2 = new StringBuilder(bytes.Length * 8);

            // Convert first byte to binary.
            var binary = Convert.ToString(bytes[idx], 2);

            // Ensure leading zero exists if value is positive.
            if (binary[0] != '0' && bigint.Sign == 1)
            {
               // base2.Append('0');
            }

            // Append binary string to StringBuilder.
            base2.Append(binary);

            // Convert remaining bytes adding leading zeros.
            for (idx--; idx >= 0; idx--)
            {
                base2.Append(Convert.ToString(bytes[idx], 2).PadLeft(8, '0'));
            }

            return base2.ToString();
        }

  
        public static string ToHexadecimalString(this BigInteger bigint)
        {
            return bigint.ToString("X");
        }
      
    

        public static string ToOctalString(this BigInteger bigint)
        {
            var bytes = bigint.ToByteArray();
            var idx = bytes.Length - 1;

            // Create a StringBuilder having appropriate capacity.
            var base8 = new StringBuilder(((bytes.Length / 3) + 1) * 8);

            // Calculate how many bytes are extra when byte array is split
            // into three-byte (24-bit) chunks.
            var extra = bytes.Length % 3;

            // If no bytes are extra, use three bytes for first chunk.
            if (extra == 0)
            {
                extra = 3;
            }

            // Convert first chunk (24-bits) to integer value.
            int int24 = 0;
            for (; extra != 0; extra--)
            {
                int24 <<= 8;
                int24 += bytes[idx--];
            }

            // Convert 24-bit integer to octal without adding leading zeros.
            var octal = Convert.ToString(int24, 8);

            // Ensure leading zero exists if value is positive.
            if (octal[0] != '0' && bigint.Sign == 1)
            {
                base8.Append('0');
            }

            // Append first converted chunk to StringBuilder.
            base8.Append(octal);

            // Convert remaining 24-bit chunks, adding leading zeros.
            for (; idx >= 0; idx -= 3)
            {
                int24 = (bytes[idx] << 16) + (bytes[idx - 1] << 8) + bytes[idx - 2];
                base8.Append(Convert.ToString(int24, 8).PadLeft(8, '0'));
            }

            return base8.ToString();
        }


        public static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }


        public static byte[] CopyArray(byte[] s, int start = 0, int count = -1 )
        {
            int l = s.Length;
            if(count != -1) l= count;

            byte[] ret = new byte[l];

            for(int i = start; i < l+start; i++)
            {
                if(i < s.Length)
                {
                    ret[i - start] = s[i];
                }
                
            }


            return ret;
        }

        public static byte[] MergeArray(byte[] a, byte[] b )
        {
            var ret = new byte[a.Length + b.Length];
            for (int i = 0; i < a.Length; i++)
            {
                ret[i] = a[i];
            }
            for (int i = 0; i < b.Length; i++)
            {
                ret[i+a.Length] = b[i];
            }


            return ret;

        }

        public static byte[] invert(byte[] inv)
        {

            var ret = new List<byte>();
            for (int i = inv.Length - 1; i >= 0; i--) {
              var cr = inv[i] ;
              cr = (byte) (      cr >> 7 | (cr >> 5) &2 | (cr >> 3) &4 | (cr >> 1) &8 | (cr << 1) &16 | (cr << 3) &32 | (cr << 5) &64 | (cr << 7) &128  );
              ret.Add(cr);
            }

            return ret.ToArray();
        }

        public static byte[] addzero(byte[] inv, bool reorder = false)
        {

            var ret = new List<byte>();

            if (reorder != true) {
              ret.Add(0) ;
            }
            for (int i = 0; i < inv.Length; i++) {
                ret.Add(inv[i]); 
            }

            if (reorder == true) {
                ret.Add(0);
                ret.Reverse();
            }
            return ret.ToArray();
        }
    }

    }
