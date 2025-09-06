using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Formats.Asn1;


namespace DSTUSign
{
    public class Curve
    {
        private byte[] ks;
        private int kofactor;
        public int m;
        public Field order { get; }
        public Field a { get; } 

        private Field b;
        public Point bp { get; }

        public Curve(AsnReader param,bool le=false)
        {
            var test = param.PeekTag();
            if(test.TagValue == 6)
            {
                var oid = param.ReadObjectIdentifier();
                if (oid == "1.2.804.2.1.1.1.1.3.1.1.2.9") //DSTU_PB_431
                { 
                     this.a = new Field(1,this) ; 
                     this.b = new Field("03CE10490F6A708FC26DFE8C3D27C4F94E690134D5BFF988D8D28AAEAEDE975936C66BAC536B18AE2DC312CA493117DAA469C640CAF3",16, this); 
                     this.order = new Field("3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBA3175458009A8C0A724F02F81AA8A1FCBAF80D90C7A95110504CF", 16, this);
                     var x = new Field("1A62BA79D98133A16BBAE7ED9A8E03C32E0824D57AEF72F88986874E5AAE49C27BED49A2A95058068426C2171E99FD3B43C5947C857D", 16, this);
                     var y = new Field("70B5E1E14031C1F70BBEFE96BDDE66F451754B4CA5F48DA241F331AA396B8D1839A855C1769B1EA14BA53308B5E2723724E090E02DB9", 16, this);
                     this.bp = new Point(x, y);
             
                     this.m = 431;
                     this.ks = new byte[3];
                     this.ks[0] = 1;
                     this.ks[1] = 3;
                     this.ks[2] = 5;
                     this.kofactor = 4;

                }
                if (oid == "1.2.804.2.1.1.1.1.3.1.1.2.6") //DSTU_PB_257
                {
                     this.a = new Field(0,this); 
                     this.b = new Field("01CEF494720115657E18F938D7A7942394FF9425C1458C57861F9EEA6ADBE3BE10", 16, this);
                     this.order = new Field("800000000000000000000000000000006759213AF182E987D3E17714907D470D", 16, this);
                     var x = new Field("2A29EF207D0E9B6C55CD260B306C7E007AC491CA1B10C62334A9E8DCD8D20FB7", 16, this);
                     var y = new Field("010686D41FF744D4449FCCF6D8EEA03102E6812C93A9D60B978B702CF156D814EF", 16, this);
                     this.bp = new Point(x, y);
             
                     this.m = 257;
                     this.ks = new byte[1];
                     this.ks[0] = 12;
  
                     this.kofactor = 4;


                }
                return;
            }

            var seq = param.ReadSequence();
            var seq2 = seq.ReadSequence();

            var a = seq.ReadInteger();
            this.a = new Field(a, this);
            byte[] b = seq.ReadOctetString();

            if (le)
            {
                b = b.Reverse().ToArray();
            }
            this.b = new Field(b, this);

            var order = seq.ReadInteger();
            this.order = new Field(order,this);
            byte[] bp= seq.ReadOctetString();
            if (le)
            {
                bp = bp.Reverse().ToArray();
            }


            this.m = (int)seq2.ReadInteger();

            var t = seq2.PeekTag().TagValue;

            if (t == 2)
            {
                this.ks = new byte[1];
                this.ks[0] = (byte)seq2.ReadInteger();
            }
            if (t == 16)
            {
                this.ks = new byte[3];
                var seq3 = seq2.ReadSequence();

                this.ks[0] = (byte)seq3.ReadInteger();
                this.ks[1] = (byte)seq3.ReadInteger();
                this.ks[2] = (byte)seq3.ReadInteger();
            }

    
            this.bp = this.expand(new Field(bp, this));

        }
        public Curve(string uid, bool le = false)
        {

        }

        public Point expand(Field f)
        {
            
            var bit = f.testBit(0);
            f.setBit(0, 0);
            var trace = f.trace() ;

            if ((1 == trace && 0 == (int) this.a.value) || (0 == trace && 1 == (int)this.a.value)) {
               f.setBit(0, 1);
            }
           
            var x2=f.mulmod(f);
            
            var y=x2.mulmod(f);
            

            if (1 == (int) this.a.value) {
               y=y.add(x2);
            }
            y=y.add(this.b);
            x2=x2.invert();
            y=y.mulmod(x2);
            y = this.fsquad(y).clone();

            trace = y.trace();
            if ((0 == trace && 1 ==  bit) || (1 == trace && 0 ==  bit)) {
              bit = y.testBit(0);
              y.setBit(0, 1 ^ bit  );
            }
            y=y.mulmod(f);

            return new Point(f,y);
        }

        public Field fsquad(Field v)
        {
            var mod = this.getModulo();


           var bitl_m = this.m;
           var range_to = (bitl_m - 1) / 2;
           v=v.mod();
           var val_a = v.clone() ;

           var val_z = val_a.clone();


           for (int idx = 1; idx <= range_to; idx += 1) {

                val_z =val_z.mulmod(val_z);
                val_z= val_z.mulmod(val_z);

                val_z =val_z.add(val_a);
            }
            var val_w = val_z.clone();
            val_w =val_w.mulmod(val_z);
            val_w= val_w.add(val_z);

            if (val_w.compare(val_a) == 0) {
                val_z = val_z.mod();

                return val_z;
            }

            throw new Exception("squad eq fail");
        }
        public Field getModulo()
        {
            Field m = Field.get1(this);
            m.value = m.value << ( this.m);
            //m.setBit(this.m, true);

            m.setBit(0, 1);
            foreach ( var v  in this.ks) {
                m.setBit((int)v, 1);
            }


            return m;
        }

        public Field truncate(Field value)
        {
            var bitl_o = this.order.getBitLength();

            var xbit = value.getBitLength();
            var ret = value.clone();
            var ret2 = value.clone();
            while (bitl_o <= xbit) {
              ret.setBit(xbit - 1, 0);
              xbit = ret.getBitLength();
            }

            return ret.clone();
        }
        public Field random()
        {
            var rnd = new Random();

            var r = new Field(rnd.Next(), this);
           
            r = this.truncate(r);

            return r;
        }

    }
}
