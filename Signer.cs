using System;
using System.CodeDom;
using System.Collections.Generic;
using System.Data;
using System.Formats.Asn1;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices.ComTypes;
using System.Runtime.Remoting.Contexts;
using System.Text;
using System.Threading.Tasks;

namespace DSTUSign
{
    /// <summary>
    ///  класс  для  подписи-верификации
    /// </summary>
    public class Signer
    {



        /// <summary>
        /// накладывает  ЭЦП
        /// </summary>
        /// <param name="message">Подписываемый локумент или  соообщение</param>
        /// <param name="key">ключ</param>
        /// <param name="cert">сертификат</param>
        ///  <param name= "detached" > открепленная подпись</param>
        /// <returns></returns>
        public static byte[] sign(byte[] message, Priv key, Cert cert, bool detached= false)
        {
 
            var msghash = Hash.hash(message);

            var serthash = cert.getHash();

      
            var context = new Asn1Tag(TagClass.ContextSpecific, 0);
            var context1 = new Asn1Tag(TagClass.ContextSpecific, 1);
            var context4 = new Asn1Tag(TagClass.ContextSpecific, 4);


            var r = new AsnReader(new ReadOnlyMemory<byte>(cert.raw), AsnEncodingRules.DER);


            var seq = r.ReadSequence();
            var seq2 = seq.ReadSequence();

            var sv = seq2.ReadSequence(context);
     
            var serial = seq2.ReadInteger() ;
            seq2.ReadSequence();

            var issuer = seq2.PeekEncodedValue();



            var attrnWriter = new AsnWriter(AsnEncodingRules.DER);
            attrnWriter.PushSequence(context);
            //1
            attrnWriter.PushSequence();
            attrnWriter.WriteObjectIdentifier("1.2.840.113549.1.9.16.2.47");
            attrnWriter.PushSetOf();
            attrnWriter.PushSequence();
            attrnWriter.PushSequence();
            attrnWriter.PushSequence();
            attrnWriter.PushSequence();
            attrnWriter.WriteObjectIdentifier("1.2.804.2.1.1.1.1.2.1");
            attrnWriter.PopSequence();
            attrnWriter.WriteOctetString(serthash);

            attrnWriter.PushSequence();
            attrnWriter.PushSequence();
            attrnWriter.PushSequence(context4);
            attrnWriter.WriteEncodedValue(issuer.Span);
            attrnWriter.PopSequence(context4); 
            attrnWriter.PopSequence();

            attrnWriter.WriteInteger(serial);
            attrnWriter.PopSequence();

            attrnWriter.PopSequence();

            attrnWriter.PopSequence();
            attrnWriter.PopSequence();
            attrnWriter.PopSetOf();
            attrnWriter.PopSequence();

            //2
            attrnWriter.PushSequence();
            attrnWriter.WriteObjectIdentifier("1.2.840.113549.1.9.3");
            attrnWriter.PushSetOf();
            attrnWriter.WriteObjectIdentifier("1.2.840.113549.1.7.1");
            attrnWriter.PopSetOf();
            attrnWriter.PopSequence();

            //3
            attrnWriter.PushSequence();
            attrnWriter.WriteObjectIdentifier("1.2.840.113549.1.9.4");
            attrnWriter.PushSetOf();
            attrnWriter.WriteOctetString(msghash);
            attrnWriter.PopSetOf();
            attrnWriter.PopSequence();

            //4
            attrnWriter.PushSequence();
            attrnWriter.WriteObjectIdentifier("1.2.840.113549.1.9.5");
            attrnWriter.PushSetOf();
            attrnWriter.WriteUtcTime(new DateTimeOffset(DateTime.Now));
            attrnWriter.PopSetOf();
            attrnWriter.PopSequence();
            
            attrnWriter.PopSequence(context);

            var attrseq = attrnWriter.Encode();
            var attrset = Util.CopyArray(attrseq);
            attrset[0] = 49;

            
            var attrhash =  Hash.hash(attrset);
          
            var sign =  key.sign(attrhash);
            

            var asnWriter = new AsnWriter(AsnEncodingRules.DER);
            asnWriter.PushSequence();
            asnWriter.WriteObjectIdentifier("1.2.840.113549.1.7.2");
            asnWriter.PushSequence(context);
            asnWriter.PushSequence();
         
            asnWriter.WriteInteger(1); //version
            //akgo
              asnWriter.PushSetOf();
                asnWriter.PushSequence();
                asnWriter.WriteObjectIdentifier("1.2.804.2.1.1.1.1.2.1"); //gost89
               asnWriter.PopSequence();
                asnWriter.PopSetOf();
        
            
            //data
            asnWriter.PushSequence( );

            asnWriter.WriteObjectIdentifier("1.2.840.113549.1.7.1");

            if (!detached)
            {
                asnWriter.PushSequence(context);

                asnWriter.WriteOctetString(message);

                asnWriter.PopSequence(context);
            }
 
            asnWriter.PopSequence();

            //cert
            asnWriter.PushSequence(context);
            asnWriter.WriteEncodedValue(cert.raw);

            asnWriter.PopSequence(context);

            //signerinfo
            asnWriter.PushSetOf();
            asnWriter.PushSequence();

            asnWriter.WriteInteger(1);

            asnWriter.PushSequence();
            asnWriter.WriteEncodedValue(issuer.Span);
            asnWriter.WriteInteger(serial);
            asnWriter.PopSequence();
            
            asnWriter.PushSequence();
            asnWriter.WriteObjectIdentifier("1.2.804.2.1.1.1.1.2.1");
            asnWriter.PopSequence();
            
            asnWriter.WriteEncodedValue(attrseq);

            

            asnWriter.PushSequence(); 
            asnWriter.WriteObjectIdentifier("1.2.804.2.1.1.1.1.3.1.1");
            asnWriter.PopSequence();
            asnWriter.WriteOctetString(sign);


            if (false) ////  todo  timestamp
            {
                var tsp = getTimestamp(cert.tsplinc, msghash).GetAwaiter().GetResult();
                var t = tsp.PeekEncodedValue();
                asnWriter.PushSequence(context1);
                asnWriter.PushSequence();
                asnWriter.WriteObjectIdentifier("1.2.840.113549.1.9.16.2.14");
                asnWriter.PushSetOf();
                asnWriter.WriteEncodedValue(t.Span); 
                asnWriter.PopSetOf();
                asnWriter.PopSequence();
                asnWriter.PopSequence(context1);

            }

            asnWriter.PopSequence();



                asnWriter.PopSetOf();
            asnWriter.PopSequence();
          
            asnWriter.PopSequence(context);
            
            asnWriter.PopSequence();
            var der = asnWriter.Encode();
   
            return der;
        }
        /// <summary>
        /// Извлекает  данные  с подписаного  сообщения
        /// </summary>
        /// <param name="signedmsg"></param>
        /// <returns></returns>
        public static byte[] decrypt(byte[] signedmsg)
        {

            var r = new AsnReader(new ReadOnlyMemory<byte>(signedmsg), AsnEncodingRules.DER);
            var seq = r.ReadSequence();
            var oid = seq.ReadObjectIdentifier();
            if (oid != "1.2.840.113549.1.7.2")
            {
                throw new Exception("Not signed data");
            }

            var context = new Asn1Tag(TagClass.ContextSpecific, 0);

            var seq2 = seq.ReadSequence(context);
            
            var seq3 = seq2.ReadSequence();
            seq3.ReadInteger();
            seq3.ReadSetOf();
            var ec = seq3.ReadSequence();
            ec.ReadObjectIdentifier();
            var ecct = ec.ReadSequence(context);
 
            return ecct.ReadOctetString();
       

            
        }

        /// <summary>
        /// проверка  ЭЦП
        /// </summary>
        /// <param name="signedmsg"></param>
        /// <returns></returns>
        public static bool check(byte[] signedmsg)
        {

            var r = new AsnReader(new ReadOnlyMemory<byte>(signedmsg), AsnEncodingRules.DER);
            var seq = r.ReadSequence();
            var oid = seq.ReadObjectIdentifier();
            if (oid != "1.2.840.113549.1.7.2")
            {
                throw new Exception("Not signed data");
            }

            var context = new Asn1Tag(TagClass.ContextSpecific, 0);

            var seq2 = seq.ReadSequence(context);

            var seq3 = seq2.ReadSequence();
            seq3.ReadInteger();
            seq3.ReadSetOf();
            seq3.ReadSequence();
            var cc = seq3.ReadSequence(context);
          //  var cert = cc.ReadSequence();
              var bb = cc.PeekEncodedValue();
         

       //     var asnWriter = new AsnWriter(AsnEncodingRules.DER);
       //     asnWriter.WriteEncodedValue(bb.Span);
       //     var certder = asnWriter.Encode();

            var cert =    new Cert(bb.ToArray());


            var si = seq3.ReadSetOf( ).ReadSequence();
            si.ReadInteger();
            si.ReadSequence();
            si.ReadSequence();
            var attr = si.ReadSequence(context);
            var attr1 = attr.PeekEncodedValue();
            attr.ReadSequence();
            var attr2 = attr.PeekEncodedValue();
            attr.ReadSequence();
            var attr3 = attr.PeekEncodedValue();
            attr.ReadSequence();
            var attr4 = attr.PeekEncodedValue();
            
  
            var asnWriter = new AsnWriter(AsnEncodingRules.DER);
            asnWriter.PushSequence();
            asnWriter.WriteEncodedValue(attr1.Span);
            asnWriter.WriteEncodedValue(attr2.Span);
            asnWriter.WriteEncodedValue(attr3.Span);
            asnWriter.WriteEncodedValue(attr4.Span);
            asnWriter.PopSequence();
            var attrder = asnWriter.Encode();
            attrder[0] = 49; //replace  to  set


            var hash = Hash.hash(attrder);
            si.ReadSequence();
            var h =si.ReadOctetString();

            var b =   cert.pub().verify(hash, h);
        
            return b;
        }

        /// <summary>
         ///получение  метки  времени с  TSP сервера
        /// </summary>
        /// <param name="link"></param>
        /// <param name="hash"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        private static async Task<AsnReader> getTimestamp(string link,byte[] hash)
        {


            var asnWriter = new AsnWriter(AsnEncodingRules.DER);
            asnWriter.PushSequence();
            asnWriter.WriteInteger(1);
            asnWriter.PushSequence();
            asnWriter.PushSequence();
            asnWriter.WriteObjectIdentifier("1.2.804.2.1.1.1.1.2.1");
            asnWriter.PopSequence();
            asnWriter.WriteOctetString(hash);
            asnWriter.PopSequence();
            asnWriter.PopSequence();
            var der = asnWriter.Encode();


            var client = new HttpClient();


            var content =  new ByteArrayContent(der);
            content.Headers.ContentType = new MediaTypeHeaderValue("application/tsp-request");

            var stream = await client.PostAsync(link,content);

            byte[] resu = await stream.Content.ReadAsByteArrayAsync();

            var r = new AsnReader(new ReadOnlyMemory<byte>(resu), AsnEncodingRules.DER);
            var ret = r.ReadSequence();

            int status = (int)ret.ReadSequence().ReadInteger();
            if(status != 0)
            {
                throw new Exception("TSP not allowed");
            }


            return ret;
        }
    }
}

 