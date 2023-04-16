using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Formats.Asn1;
 

namespace DSTUSign
{
   /// <summary>
   /// Публичный ключ
   /// </summary>
    public class Pub
    {
        public Point q { get; }
        public Pub(Point v)
        {
            this.q = v;
        }
        public Pub(Field v)
        {
            var t= v.curve.bp.mul(v);
            this.q = t.negate(); 
        }
        /// <summary>
        /// проверка  подписи
        /// </summary>
        /// <param name="message"></param>
        /// <param name="sign"></param>
        /// <returns></returns>
        public bool verify(byte[] message, byte[] sign)
        {

            message =  message.Reverse().ToArray();
            message =  Util.addzero(message); 

        
            var hv = new Field(message, this.q.x.curve);

            sign = sign.Reverse().ToArray();

            var sb = Util.CopyArray(sign, 0, sign.Length/2);
            var rb = Util.CopyArray(sign, sign.Length/2, sign.Length / 2);
            sb = Util.addzero(sb);
            rb = Util.addzero(rb);

            var r = new Field(rb, this.q.x.curve);
            var s = new Field(sb, this.q.x.curve);

            var Q = this.q.mul(r);
            var S = this.q.x.curve.bp.mul(s);
            var pr = S.add(Q);
        
            var r1 = pr.x.mulmod(hv);

            r1 = this.q.x.curve.truncate(r1);
            var b = r1.compare(r);
            return b == 0;
        }

    }
}
