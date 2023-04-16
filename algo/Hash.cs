using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.WindowsRuntime;

namespace DSTUSign
{
    public class Hash
    {
        private byte[] left  ;
        private int len = 0;
        private byte[] U ;
        private byte[] W ;
        private byte[] V ;
        private byte[] _S ;
        private byte[] Key ;
        private byte[] c8buf ;
        private byte[] H ;
        private byte[] S ;
        private byte[] buf ;
        private int[] ab2 ;

        public Hash()
        {
            this.H =  new byte[32] ;
            this.buf = new byte[32];
            this.S = new byte[32];
            this._S = new byte[32];
            this.ab2 = new int[4];
            this.left = new byte[0];
        }
        public  void update(byte[] block)
        {
            var block32 = Util.CopyArray(block);
            var off = 0;
            //todo
            while (block.Length - off >= 32) {
                this.H = step(this.H, block32);
                this.S = add_blocks(32, this.S, block32);
                off += 32;
                block32 = Util.CopyArray(block, off, block.Length - off) ;

                
            }

            this.len += off;
            if(block32.Length > 0)
            {
                this.left = block32;
            }
        }
        public byte[] finish(  )
        {
            byte[] ret = new byte[32];
            var buf = Util.CopyArray(this.buf);
            var fin_len = this.len;
            if (this.left.Length > 0)
            {
                for (int i = 0; i < this.left.Length; i++) {
                   buf[i] = this.left[i];
                }
                this.H = this.step(this.H, buf);
                this.S = this.add_blocks(32, this.S, buf);
                fin_len += this.left.Length;
                this.left = new byte[0];

                for (int i = 0; i < 32; i++) {
                  buf[i] = 0;
                }
            }
            fin_len <<= 3;
            int idx = 0;
            while (fin_len > 0) {
                buf[idx++] = (byte)(fin_len & 0xff);
                fin_len >>= 8;
            }

            this.H = this.step(this.H, buf);
            this.H = this.step(this.H, this.S);

            for (int i = 0; i < 32; i++) {
                 ret[i] = this.H[i];
            }
            fin_len <<= 3;

            return ret;
        }

        public void update32(byte[]  block32)
        {
            this.H = step(this.H, block32);
            this.S = add_blocks(32,this.S, block32);
            this.len += 32;
        }

        private   byte[] step(byte[] H, byte[] M)
        {
            var U = new Byte[32];
            var V = new Byte[32];
            byte[] S = this._S;
            var W = Hash.xor_blocks(H, M);
            var Key = Hash.swap_bytes(W);

            var gost = new Gost();
            gost.key(Key);
            var _S=gost.crypt64(H);
            for (int i = 0; i < 8; i++) {
               S[i] = _S[i];
            }

            U = Hash.circle_xor8(H, U);
            V = Hash.circle_xor8(M, V);
            V = Hash.circle_xor8(V, V);
            W = Hash.xor_blocks(U, V);
            Key = Hash.swap_bytes(W);
            gost.key(Key);

            _S = gost.crypt64( Util.CopyArray(H, 8, 8));

            for (int i = 0; i < 8; i++) {
               S[i + 8] = _S[i];
            }
            
            U = Hash.circle_xor8(U, U);
            
            U[31] = (byte)~U[31];
            U[29] = (byte)~U[29];
            U[28] = (byte)~U[28];
            U[24] = (byte)~U[24];
            U[23] = (byte)~U[23];
            U[20] = (byte)~U[20];
            U[18] = (byte)~U[18];
            U[17] = (byte)~U[17];
            U[14] = (byte)~U[14];
            U[12] = (byte)~U[12];
            U[10] = (byte)~U[10];
            U[8] = (byte)~U[8];
            U[7] = (byte)~U[7];
            U[5] = (byte)~U[5];
            U[3] = (byte)~U[3];
            U[1] = (byte)~U[1];

            V = Hash.circle_xor8(V, V);
            V = Hash.circle_xor8(V, V);
            W = Hash.xor_blocks(U, V);
            Key = Hash.swap_bytes(W);
            gost.key(Key);
            _S = gost.crypt64(Util.CopyArray(H, 16, 8));
            for (int i = 0; i < 8; i++) {
               S[i + 16] = _S[i];
            }


            U = Hash.circle_xor8(U, U);
            V = Hash.circle_xor8(V, V);
            V = Hash.circle_xor8(V, V);
            W = Hash.xor_blocks(U, V);
            Key = Hash.swap_bytes(W);
            gost.key(Key);
            _S = gost.crypt64(Util.CopyArray(H, 24, 8));
            for (int i = 0; i < 8; i++) {
               S[i + 24] = _S[i];
            }
            for (int i = 0; i < 12; i++) {
               S = Hash.transform_3(S);
            }
            _S = Hash.xor_blocks(S, M);
            for (int i = 0; i < _S.Length; i++) {
               S[i] = _S[i];
            }

            S = Hash.transform_3(S);

            _S = Hash.xor_blocks(S, H);
            for (int i = 0; i < _S.Length; i++) {
              S[i] = _S[i];
            }

            for (int i = 0; i < 61; i++) {
              S = Hash.transform_3(S);
            }
            for (int i = 0; i < 32; i++) {
              H[i] = S[i];
            }
            this.Key = Key;
            this._S = S;

            return H;


            
        }

        private   byte[] add_blocks(int n, byte[] left, byte[] right)
        {
            this.ab2[2] = 0;
            this.ab2[3] = 0;

            for (int i = 0; i < n; i++) {
                this.ab2[0] = left[i];
                this.ab2[1] = right[i];
                this.ab2[2] = this.ab2[0] + this.ab2[1] + this.ab2[3];
                left[i] = (byte)( this.ab2[2] & 0xff);
                this.ab2[3] = this.ab2[2] >> 8;
            }

            // return $this->ab2[3];
            return left;
        }


        private static byte[] xor_blocks(byte[] a, byte[] b)
        {
            byte[] ret = new byte[a.Length] ;

            for (int i = 0; i <a.Length; i++) {
               ret[i] = (byte)((int)a[i] ^ (int)b[i] );
            }
            return ret;
            
        }
        private static byte[] swap_bytes(byte[] w )
        {
            byte[]k = new byte[w.Length] ;
            for (int i = 0; i < 4; i++) {
                for (int j = 0; j < 8; j++) {
                    k[i + 4 * j] = w[8 * i + j];
                }
            }
            return k;
        }
        private static byte[] circle_xor8(byte[] w, byte[] k)
        {
            byte[] c8buf = new byte[8];
                
            for (int i = 0; i < 8; i++) {
                c8buf[i] = w[i];
            }
            for (int i = 0; i < 24; i++) {
                k[i] = w[i + 8];
            }
            for (int i = 0; i < 8; i++) {
               k[i + 24] = (byte)(c8buf[i] ^ k[i]);
            }
            return k;
        }
        private static byte[] transform_3(byte[] data)
        {
            uint t16 = (uint) ((data[0] ^ data[2] ^ data[4] ^ data[6] ^ data[24] ^ data[30]) |
                ((data[1] ^ data[3] ^ data[5] ^ data[7] ^ data[25] ^ data[31]) << 8));

        
            //data = Util.CopyArray(data, 2,data.Length-2);
            for(int i = 2; i < 32; i++){
                data[i - 2] = data[i];
            }
            data[30] = (byte)(t16 & 0xff);
            data[31] = (byte)(t16 >> 8);

            return data;
        }


        public  static byte[] hash(byte[] data)
        {
            var hash = new Hash();
            hash.update(data);
            return  hash.finish();

        }

    }
}