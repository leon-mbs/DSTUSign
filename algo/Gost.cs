using System;
using System.Runtime.ConstrainedExecution;

namespace DSTUSign
{
    public class Gost
    {
        public uint[] k;
        public uint[] k87 ;
        public uint[] k65 ;
        public uint[] k43 ;
        public uint[] k21 ;
        public uint[] n ;
        public byte[] gamma ;

        public Gost()
        {
           var box = new SBox();
           this.boxinit(box);
        }

        private void boxinit(SBox box)
        {
            this.k87 = new uint[256];
            this.k65 = new uint[256];
            this.k43 = new uint[256];
            this.k21 = new uint[256];
            this.k = new uint[8];

            for (uint i = 0; i < 256; i++) {
                
                uint r = i >> 4;

                this.k87[i] = (uint)((box.k8[r] << 4) | box.k7[i & 15]) << 24;
                this.k65[i] = (uint)((box.k6[r] << 4) | box.k5[i & 15]) << 16;
                this.k43[i] = (uint)((box.k4[r] << 4) | box.k3[i & 15]) << 8;
                this.k21[i] = (uint)(box.k2[r] << 4) | box.k1[i & 15];

                 

            }


        }

        public  void key(byte[] k)
        {
            int j = 0;
            for (int i = 0; i < 8; i++)
            {
               
               this.k[i] = (uint)(k[j] | (k[j + 1] << 8) | (k[j + 2] << 16) | (k[j + 3] << 24) );
               j += 4;
                //   if (this.k[i] < 0) {
                //      this.k[i] = 0xFFFFFFFF + 1 + $this.k[$i];
                //  }
            }
        }
        
    
        public byte[] crypt64(byte[] clear)
        {
            uint[] n = new uint[2];
            n[0] = (uint) (clear[0] | (clear[1] << 8) | (clear[2] << 16) | (clear[3] << 24) );
            n[1] = (uint)(clear[4] | (clear[5] << 8) | (clear[6] << 16) | (clear[7] << 24) );

            n[1] ^= this.pass(n[0] + this.k[0]);
            n[0] ^= this.pass(n[1] + this.k[1]);
            n[1] ^= this.pass(n[0] + this.k[2]);
            n[0] ^= this.pass(n[1] + this.k[3]);
            n[1] ^= this.pass(n[0] + this.k[4]);
            n[0] ^= this.pass(n[1] + this.k[5]);
            n[1] ^= this.pass(n[0] + this.k[6]);
            n[0] ^= this.pass(n[1] + this.k[7]);

            n[1] ^= this.pass(n[0] + this.k[0]);
            n[0] ^= this.pass(n[1] + this.k[1]);
            n[1] ^= this.pass(n[0] + this.k[2]);
            n[0] ^= this.pass(n[1] + this.k[3]);
            n[1] ^= this.pass(n[0] + this.k[4]);
            n[0] ^= this.pass(n[1] + this.k[5]);
            n[1] ^= this.pass(n[0] + this.k[6]);
            n[0] ^= this.pass(n[1] + this.k[7]);

            n[1] ^= this.pass(n[0] + this.k[0]);
            n[0] ^= this.pass(n[1] + this.k[1]);
            n[1] ^= this.pass(n[0] + this.k[2]);
            n[0] ^= this.pass(n[1] + this.k[3]);
            n[1] ^= this.pass(n[0] + this.k[4]);
            n[0] ^= this.pass(n[1] + this.k[5]);
            n[1] ^= this.pass(n[0] + this.k[6]);
            n[0] ^= this.pass(n[1] + this.k[7]);

            n[1] ^= this.pass(n[0] + this.k[7]);
            n[0] ^= this.pass(n[1] + this.k[6]);
            n[1] ^= this.pass(n[0] + this.k[5]);
            n[0] ^= this.pass(n[1] + this.k[4]);
            n[1] ^= this.pass(n[0] + this.k[3]);
            n[0] ^= this.pass(n[1] + this.k[2]);
            n[1] ^= this.pass(n[0] + this.k[1]);
            n[0] ^= this.pass(n[1] + this.k[0]);

            byte[]  ret = new byte[8];

            ret[0] = (byte)(n[1] & 0xff);
            ret[1] = (byte)((n[1] >> 8) & 0xff);
            ret[2] = (byte)((n[1] >> 16) & 0xff);
            ret[3] = (byte)((n[1] >> 24));
            ret[4] = (byte)(n[0] & 0xff);
            ret[5] = (byte)((n[0]>> 8) & 0xff);
            ret[6] = (byte)((n[0]>> 16) & 0xff);
            ret[7] = (byte)((n[0] >> 24));

            return ret;
        }


        private uint pass (uint x)
        {
            
            x = this.k87[(x >> 24) & 255] |
                this.k65[(x >> 16) & 255] |
                this.k43[(x >> 8) & 255] |
                this.k21[x & 255];

            x = (x << 11) | x >> (32 - 11);

            return x & 0xffffffff;
        }

        public byte[] decrypt(byte[] cypher)
        {
            int blocks = (int)Math.Ceiling(cypher.Length / 8.0);
            byte[] ret = new byte[0]; ;
            while (blocks-- >0) {
                var  off = blocks * 8;
                var block = Util.CopyArray(cypher, off, 8);
                var outblock = this.decrypt64(block);
                ret = Util.MergeArray(outblock, ret);
            }

            if (ret.Length != cypher.Length)
            {
               ret = Util.CopyArray(ret, 0, cypher.Length);
            }

            return ret;
        }


        public byte[] decrypt64( byte[] cypher)
        {
            var n = new uint[2];
            n[0] =  (uint)( cypher[0] | (cypher[1] << 8) | (cypher[2] << 16) | (cypher[3] << 24) );
            n[1] =  (uint)(  cypher[4] | (cypher[5] << 8) | (cypher[6] << 16) | (cypher[7] << 24) );

            n[1] ^= this.pass(n[0] + this.k[0]);
            n[0] ^= this.pass(n[1] + this.k[1]);
            n[1] ^= this.pass(n[0] + this.k[2]);
            n[0] ^= this.pass(n[1] + this.k[3]);
            n[1] ^= this.pass(n[0] + this.k[4]);
            n[0] ^= this.pass(n[1] + this.k[5]);
            n[1] ^= this.pass(n[0] + this.k[6]);
            n[0] ^= this.pass(n[1] + this.k[7]);

            n[1] ^= this.pass(n[0] + this.k[7]);
            n[0] ^= this.pass(n[1] + this.k[6]);
            n[1] ^= this.pass(n[0] + this.k[5]);
            n[0] ^= this.pass(n[1] + this.k[4]);
            n[1] ^= this.pass(n[0] + this.k[3]);
            n[0] ^= this.pass(n[1] + this.k[2]);
            n[1] ^= this.pass(n[0] + this.k[1]);
            n[0] ^= this.pass(n[1] + this.k[0]);

            n[1] ^= this.pass(n[0] + this.k[7]);
            n[0] ^= this.pass(n[1] + this.k[6]);
            n[1] ^= this.pass(n[0] + this.k[5]);
            n[0] ^= this.pass(n[1] + this.k[4]);  //3466386349
            n[1] ^= this.pass(n[0] + this.k[3]);
            n[0] ^= this.pass(n[1] + this.k[2]);
            n[1] ^= this.pass(n[0] + this.k[1]);
            n[0] ^= this.pass(n[1] + this.k[0]);

            n[1] ^= this.pass(n[0] + this.k[7]);
            n[0] ^= this.pass(n[1] + this.k[6]);
            n[1] ^= this.pass(n[0] + this.k[5]);
            n[0] ^= this.pass(n[1] + this.k[4]);
            n[1] ^= this.pass(n[0] + this.k[3]);
            n[0] ^= this.pass(n[1] + this.k[2]);
            n[1] ^= this.pass(n[0] + this.k[1]);
            n[0] ^= this.pass(n[1] + this.k[0]);

            byte[] ret = new byte[8];
            
            ret[0] = (byte)(n[1] & 0xff);
            ret[1] = (byte)((n[1] >> 8) & 0xff);
            ret[2] = (byte)((n[1]>> 16) & 0xff);
            ret[3] = (byte)((n[1]>> 24));
            ret[4] = (byte)(n[0] & 0xff);
            ret[5] = (byte)((n[0]>> 8) & 0xff);
            ret[6] = (byte)((n[0]>> 16) & 0xff);
            ret[7] = (byte)((n[0]>> 24));
            
            return ret;     //216 205 110 128 165 137 175 83
        }

        public byte[] decrypt_cfb(byte[] iv, byte[] data)
        {

            this.gamma = new byte[8]; 

            var cur_iv = new byte[8];

            for (int id = 0; id < 8; id++) {
               cur_iv[id] = iv[id];
            }

            var blocks = (int) Math.Ceiling(data.Length / 8.0);
            var clear = new byte[blocks * 8] ;

            var idx = 0;
            var off = 0;
            while ( idx < blocks) {
                off = idx++ * 8;
                var res = this.decrypt64_cfb(cur_iv, Util.CopyArray(data, off, 8));
                cur_iv = res[1];
                for (int i = 0; i < 8; i++) {
                   clear[off + i] = res[0][i];
                }
            }

            return clear;

        }


        public  byte[][] decrypt64_cfb(byte[] iv, byte[] data)
        {

            var clear = new byte[8];
            this.gamma = this.crypt64(iv);


            for (int j = 0; j < 8; j++) {
        
                iv[j] = data[j];
                clear[j] = (byte)(data[j] ^ this.gamma[j]);
            }

            var ret = new byte[2][];
            ret[0] = clear;
            ret[1] = iv;
            return ret;
        }


    }

    class SBox
    {

        public byte[] k1  ;
        public byte[] k2  ;
        public byte[] k3  ;
        public byte[] k4  ;
        public byte[] k5 ;
        public byte[] k6 ;
        public byte[] k7 ;
        public byte[] k8 ;

        public SBox()
        {
     
            string def = "0102030E060D0B080F0A0C050709000403080B0506040E0A020C0107090F0D0002080907050F000B0C010D0E0A0306040F080E090702000D0C0601050B04030A03080D09060B0F0002050C0A040E01070F0605080E0B0A040C0003070209010D08000C040906070B0203010F050E0A0D0A090D060E0B04050F01030C07000802";

            byte[] a = Util.StringToByteArray(def);

            this.k8 =  Util.CopyArray(a, 0, 16) ; 

            this.k7 = Util.CopyArray(a, 16, 16);
            this.k6 = Util.CopyArray(a, 32, 16);
            this.k5 = Util.CopyArray(a, 48, 16);
            this.k4 = Util.CopyArray(a, 64, 16);
            this.k3 = Util.CopyArray(a, 80, 16);
            this.k2 = Util.CopyArray(a, 96, 16);
            this.k1 = Util.CopyArray(a, 112, 16);
        }


  
    }

}