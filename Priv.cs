using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Formats.Asn1;
using System.Security.Cryptography;

namespace DSTUSign
{
   /// <summary>
   /// Приватный  ключ
   /// </summary>   
    public  class Priv
    {
        private Field d;
        public Priv(byte[] d, AsnReader curve,bool le = false,bool inv = false)
        {
            var c = new Curve(curve, le);
            if (le)
            {
                d = d.Reverse().ToArray();
            }
            if (inv)
            {
                d = Util.addzero(Util.invert(d));
            }


            this.d = new Field(d, c);

        }


        /// <summary>
        /// возвращает публичный ключ
        /// </summary>
        /// <returns></returns>
        public Pub pub()
        {
            return new Pub(this.d) ;
        }

        /// <summary>
        /// Подписание  сообщения
        /// </summary>
        /// <param name="message"></param>
        /// <returns></returns>
        public byte[] sign(byte[] message)
        {
            
            message = message.Reverse().ToArray();
            message = Util.addzero(message);
            var hmsg = Util.ByteArrayToString(message);
            var hv = new Field(hmsg,16, this.d.curve);
            
            var rand = this.d.curve.random();
          //  rand.value = 1;


        var eG = this.d.curve.bp.mul(rand);

        var r = hv.mulmod(eG.x);
        
        r = this.d.curve.truncate(r);
        var s = this.d.mul(r);


            var sb =   this.d.value * r.value;//  gmp_mul($this->d->value, $r->value);

        s.value = sb % d.curve.order.value;// gmp_mod($sb, $this->d->curve->order->value);


            s.value = s.value + rand.value;//  gmp_add($s->value, $rand->value);

            s.value = s.value % d.curve.order.value;// gmp_mod($s->value, $this->d->curve->order->value);
            s.value = s.value % d.curve.order.value;// gmp_mod($s->value, $this->d->curve->order->value);

            var hr = r.value.ToHexadecimalString();
            var hs = s.value.ToHexadecimalString();

            if(hr.Length < 64)
            {
                while (hr.Length < 64) hr = "0"+hr;
            }
            if (hs.Length < 64)
            {
                while (hs.Length < 64) hs = "0" + hs;
            }

            /*
            //восстанавливаем  возможные  0 после  truncate

            var ol = this.d.curve.order.getBitLength();
            var br = r.value.ToBinaryString();
            while (br.Length < ol )  {
               br = '0'+br;
            }
            //дополняем  до  кратного 8
            var l = br.Length;
            var lb = (int)(l / 8);
            if ((l % 8) > 0) lb++;

            while (br.Length < (lb * 8) )  {
               br = '0'+br;
            }
 
           var spl = Enumerable.Range(0, br.Length / 8)
                    .Select(i => br.Substring(i * 8, 8)).ToArray();


            var tmp_rl = new List<byte>();  ;

            foreach (var chunk  in spl ) {

                var d= Convert.ToInt32(chunk, 2);
                tmp_rl.Add((byte)d);
            }

            var tmp_r = tmp_rl.ToArray();
            */
            var tmp_r = Util.StringToByteArray(hr);

            var tmp_s = Util.StringToByteArray(hs);

            var mlen = tmp_s.Length;
            if (tmp_r.Length > tmp_s.Length) mlen = tmp_r.Length;
            if (tmp_s.Length > tmp_r.Length) mlen = tmp_s.Length;

            var buf = new byte[mlen * 2 + 2]; 
       
            buf[0] = 4;
            buf[1] = (byte)(mlen * 2);

            for (int idx = 0; idx < mlen; idx++) {
                var tmp = tmp_r[mlen - idx - 1];
       
                buf[idx + 2] = (byte)( tmp < 0 ? 256 +tmp: tmp);

            }

            for (int idx = 0; idx < mlen; idx++) {
               var  tmp = tmp_s[mlen - idx - 1];
                buf[idx + 2 +mlen] = (byte)( tmp < 0 ? 256 +tmp: tmp);
            }       
 
            var sign = Util.CopyArray(buf, 2, buf.Length-2);
          
        
            return sign;

          
             
        }


    }
}
