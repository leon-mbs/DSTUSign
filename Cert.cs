using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Formats.Asn1;
using System.Buffers;

namespace DSTUSign
{
    /// <summary>
    /// Сертификат
    /// </summary>
    public class Cert
    {
        public byte[] raw { get; }
        private Point publickey;

        /// <summary>
        /// серийный  номер
        /// </summary>
        public string serial { get;   }
        
        /// <summary>
       ///Владелец сертификата
        /// </summary>
        public string owner { get; }
        /// <summary>
        ///ЄДРПОУ
        /// </summary>
        public string edrpou { get; }
        /// <summary>
        /// кто  выдал
        /// </summary>
        public string issuer { get; }
        /// <summary>
        /// дата  окончания
        /// </summary>
        public string enddate { get; }
        /// <summary>
        /// Идентификатор  ключа
        /// </summary>
        public string keyid { get; }

        
        public  bool isKeyUsage { get; }
        
        /// <summary>
        ////адрес  TSP сервера
        /// </summary>
        public string tsplinc { get; }

        public Cert(byte[] raw)
        {

            this.raw = raw;
          
                 
            var r = new AsnReader(new ReadOnlyMemory<byte>(raw), AsnEncodingRules.DER);


            var seq = r.ReadSequence();
            var seq2 = seq.ReadSequence();


            var context = new Asn1Tag(TagClass.ContextSpecific, 0);

            var sv = seq2.ReadSequence(context);
            var version = (int)sv.ReadInteger();

            this.serial = seq2.ReadInteger().ToString(); ;


            var va = seq2.ReadSequence();
            var  salgo = va.ReadObjectIdentifier();
            var issuer = seq2.ReadSequence();
            var time=seq2.ReadSequence();
            var subject = seq2.ReadSequence();
 

            var pki =seq2.ReadSequence();
            var pkia = pki.ReadSequence();

            var algo = pkia.ReadObjectIdentifier();

            var curveparam = pkia.ReadSequence();


  
            var curve = new Curve(curveparam, true);
           
            int unu = 0;
            var puba = pki.ReadBitString(out unu);
            
            puba = new ArraySegment<byte>(puba, 2, puba.Length-2).ToArray();
            puba = puba.Reverse().ToArray();


            var p = new Field(puba, curve);

            this.publickey = curve.expand(p);
            var xx = this.publickey.x.value;
            var yy = this.publickey.y.value;

          

            while (issuer.HasData)
            {
                var item = issuer.ReadSetOf().ReadSequence();
                var oi = item.ReadObjectIdentifier();
                if (oi == "2.5.4.11")
                {
                    this.issuer = item.ReadCharacterString(UniversalTagNumber.UTF8String);
                }
                

            }
            while (subject.HasData)
            {
                var item = subject.ReadSetOf().ReadSequence();
                var oi = item.ReadObjectIdentifier();
                if (oi == "2.5.4.3")
                {
                    this.owner = item.ReadCharacterString(UniversalTagNumber.UTF8String);
                }
                if (oi == "2.5.4.5")
                {
                    var t = item.PeekTag();
                    if (t.TagValue == 12)
                    {
                        this.edrpou = item.ReadCharacterString(UniversalTagNumber.UTF8String);
                    }
                    if (t.TagValue == 19)
                    {

                     
                        var tt = item.ReadEncodedValue().ToArray();
                        tt = Util.CopyArray(tt, 2, tt.Length - 2);
                        this.edrpou = Encoding.ASCII.GetString(tt).Trim();
                        
                    }

                }

            }

            time.ReadUtcTime();
            this.enddate = time.ReadUtcTime().ToString();

            context = new Asn1Tag(TagClass.ContextSpecific, 3);
            var ext = seq2.ReadSequence(context).ReadSequence();
            while (ext.HasData)
            {
                var item = ext.ReadSequence(); 
                string id = item.ReadObjectIdentifier();
                if (id == "2.5.29.14")
                {
                   var ba = item.ReadOctetString();
                    

                    StringBuilder hex = new StringBuilder(ba.Length * 2);
                    foreach (byte b in ba)
                        hex.AppendFormat("{0:x2}", b);

                    this.keyid = hex.ToString();

                    continue;
                }
                if (id == "2.5.29.15")
                {
                    item.ReadBoolean();
                    var ba = item.ReadOctetString();


                    if (ba[3] == 192)
                    {
                        this.isKeyUsage = true;
                    }

                    continue;
                }
                if (id == "1.3.6.1.5.5.7.1.11")
                {
                    var ba = item.ReadOctetString();
                    var l = new AsnReader(new ReadOnlyMemory<byte>(ba), AsnEncodingRules.DER);

                    var sq = l.ReadSequence().ReadSequence();
                    
                    
                    string idl = sq.ReadObjectIdentifier();
                    if (idl == "1.3.6.1.5.5.7.48.3")
                    {

                        context = new Asn1Tag(TagClass.ContextSpecific, 6);
                        var dddd = sq.ReadOctetString(context);
                       this.tsplinc= Encoding.ASCII.GetString(dddd).Trim();
                    }
                    continue;
                }

            }


            return;
        }
        /// <summary>
        /// Публичный ключ 
        /// </summary>
        /// <returns></returns>
        public  Pub pub()
        {
            return new Pub(this.publickey);
        }

        public byte[] getHash()
        {
            var h = new Hash();
            h.update(this.raw);
            return h.finish();

        }

      

    }

}
