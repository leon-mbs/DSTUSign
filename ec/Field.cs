using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Numerics;
using System.Globalization;
using System.Security.Cryptography;


namespace DSTUSign
{
    public class Field
    {
        public Curve curve { get;   }
        public BigInteger value { get; set; }

        public Field(int val)
        {
            this.value = new BigInteger(val);

        }
        public Field(string val,int b=10, Curve curve = null)
        {
            if (b == 16)
            {
               
               this.value = BigInteger.Parse("00"+val, NumberStyles.AllowHexSpecifier);

            }
            if (b == 10)
            {
               
                this.value = BigInteger.Parse(val);
            }

            if (b == 2)
            {
                BigInteger res = 0;

                // I'm totally skipping error handling here
                foreach (char c in val)
                {
                    res <<= 1;
                    res += c == '1' ? 1 : 0;
                }
                
                this.value = res;
            }
            this.curve = curve;
        }
        public Field(byte[] val, Curve curve = null)
        {
            //  Array.Resize(ref val, val.Length+1);

            // this.value = new BigInteger(val);
            //    if(this.value < 0)
            {
                var s = "00" + Util.ByteArrayToString(val);
                this.value = BigInteger.Parse(s, NumberStyles.AllowHexSpecifier);

            }

            if (curve != null)
            {
                this.curve = curve;
            }

        }
        public Field(BigInteger val, Curve curve = null)
        {

            this.value = val;
            if (curve != null)
            {
                this.curve = curve;
            }
        }

        public bool is0()
        {
            var s = this.value.ToBinaryString();
            return s == "0";
        }

        public int testBit(int bitNum)
        {
 
            uint bytePos = (uint)bitNum >> 3;             // divide by 8
            byte bitPos = (byte)(bitNum & 0x7);    // get the lowest 5 bits

            byte mask = (byte)(1 << bitPos);
            var data = this.value.ToByteArray();
            var ret =  ((data[bytePos] | mask) == data[bytePos]);
            return ret ? 1 : 0;
        }
        public void setBit(int bitNum, int value)
        {
            var l = this.getBitLength();
            if (l < bitNum)
            {
                return;
            }
            uint bytePos = (uint)bitNum >> 3;             // divide by 8
            byte bitPos = (byte)(bitNum & 0x7);    // get the lowest 5 bits


            var data = this.value.ToByteArray();
            byte mask = (byte)(1 << (byte)(bitNum & 0x7));

            if (value==1)
                data[bytePos] |= mask;
            else
                data[bytePos] &= (byte)(~mask);

            this.value = new BigInteger(data);
        }

        public Field clone()
        {

            return new Field(this.value, this.curve);
        }



        public static Field get0(Curve c)
        {
            return new Field(0, c);
        }
        public static Field get1(Curve c)
        {
            return new Field(1, c);
        }
        public Field add(Field v)
        {
            return new Field( this.value ^ v.value,this.curve);
        }
       
        public int compare(Field v)
        {
            if (this.value < v.value) return -1;
            if (this.value > v.value) return 1;
            return 0;
        }
        public int getBitLength()
        {
            var s = this.value.ToBinaryString();
            s = s.TrimStart(new char[1] { '0' });
            return s.Length;
        }

        public int trace()
        {
            var m = this.curve.m;
            var t = this.clone();



            for (int i = 1; i <= m - 1; i++)
            {
               t= t.mulmod(t);

               t= t.add(this);

            }

            return t.testBit(0);

        }

        public Field mul(Field v)
        {
            var bag = Field.get0(this.curve);
           
            var shift = this.clone();
            int l = v.getBitLength();
            for (int i = 0; i < l; i++)
            {
                var bit = v.testBit(i);
                if (bit==1)
                {
                   bag= bag.add(shift);
                    
                }
                shift.value = shift.value << 1; 
            }

            return new Field(bag.value,this.curve);
        
        }

        public Field mod()
        {
            var m = this.curve.getModulo();
            var cmp = this.compare(m);
            if (cmp == 0)
            {
                return   Field.get0(this.curve);
                
            }
            if (cmp < 0)
            {
                return this.clone();
            }

            var rc = this.div(m);
           return new Field(  rc[1].value,this.curve);
        }
        public Field[] div(Field v)
        {
            var ret = new Field[2];

            var c = this.compare(v);
            if (c == 0)
            {
                ret[0] = Field.get1(this.curve);
                ret[1] = Field.get0(this.curve);
                return ret;
            }
            if (c < 0)
            {
                ret[0] = Field.get0(this.curve);
                ret[1] = this.clone();
                return ret;
            }

            var res = "";
            var bag = this.clone();
            var vl = v.getBitLength();
            while (true)
            {
                var bl = bag.getBitLength();
                var shift = v.clone();
                shift.value = shift.value << (bl-vl);
                bag = bag.add(shift);
                res = res + "1";
                var blnew = bag.getBitLength();
                var bdiff = bl - blnew;
              

                if (blnew < vl) {

                    var ediff = bl - vl;  //осталось  до  конца
                    if (ediff > 0) {
                        
                        res = res + new string('0', ediff);
                    }
                    var rest = bag;
                
                    ret[0] =  new Field(res,2,this.curve);
                    ret[1] = rest;
                    return ret;


                }
                if (bdiff > 1) {
                   res = res + new string('0', bdiff-1);
                }

            }

            //return ret;
        }
        public Field mulmod(Field v)
        {
           var t = this.mul(v);
           return t.mod();
        }
        public Field invert()
        {
             var r=this.mod();
             var s = this.curve.getModulo();

            var u = Field.get1(this.curve);
            var v = Field.get0(this.curve);

            var rl = r.getBitLength();
            var sl = s.getBitLength();

            while (rl > 1) {
                var j = sl - rl;

                if (j < 0) {

                    var tmp = r.clone();
                    r = s.clone();
                    s = tmp.clone(); ;
                    tmp = u.clone();
                    u = v.clone();
                    v = tmp.clone();
                    j = 0 - j;
                }

                var rs = new Field(r.value << j); 
                s=s.add(rs);
               
                var us = new Field(u.value << j);

                v=v.add(us);
                rl = r.getBitLength();
                sl = s.getBitLength();


            }
            return new Field( u.value,this.curve);
        }

       
    }
}
