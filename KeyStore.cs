using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Formats.Asn1;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Net;

using System.Runtime.ConstrainedExecution;
using System.Security.Claims;

namespace DSTUSign
{
    public  class KeyStore
    {
        /// <summary>
        /// загрузка  и распаковка  ключа (обычно key-6.dat)
        /// </summary>
        /// <param name="_keydata">содержимое  файла  хранилища  ключа</param>
        /// <param name="password">Пароль к ключу</param>
        /// <param name="cert">Сертификат</param>
        /// <returns>Приватный ключ</returns>
        public  static Priv load(byte[] _keydata,string password,Cert  cert)
        {
            var keys = new List<Priv>();

           
         
            try
            {
                var keydata = Util.CopyArray(_keydata, 57, _keydata.Length - 57);//skip pfx header
                var r = new AsnReader(new ReadOnlyMemory<byte>(keydata), AsnEncodingRules.DER);

                var bags =r.ReadSequence();
                while (bags.HasData)
                {
                    var bag = bags.ReadSequence();
                    var Oid = bag.ReadObjectIdentifier();  //1.2.840.113549.1.12.10.1.2  (PKCS #12 BagIds
                    var context = new Asn1Tag(TagClass.ContextSpecific, 0);
                    var seq = bag.ReadSequence(context);

                    var seq2 = seq.ReadSequence();
                    
                    var seq3 = seq2.ReadSequence();
                    var t = seq2.PeekTag();
                    var cryptdata = seq2.ReadOctetString();

                    Oid = seq3.ReadObjectIdentifier();
                    var pbes2 = seq3.ReadSequence();
                    var keyDerivation = pbes2.ReadSequence();
                    var encryption = pbes2.ReadSequence();

                    Oid = keyDerivation.ReadObjectIdentifier();
                    var kd = keyDerivation.ReadSequence();
                    var salt = kd.ReadOctetString();
                    var iter = kd.ReadInteger();

                    Oid = encryption.ReadObjectIdentifier();
                    kd = encryption.ReadSequence();
                    var iv = kd.ReadOctetString();
                    var sbox = kd.ReadOctetString();

                    var pass = Encoding.ASCII.GetBytes(password);

                    var key = new byte[32];
                    var pw_pad36 = new byte[32];
                    var pw_pad5C = new byte[32];
                    var ins = new byte[4];
                    ins[3] = 1;

                    for (int i = 0;i < 32; i++)
                    {
                        pw_pad36[i] = 0x36;
                        pw_pad5C[i] = 0x5C;
                    }
                    for (int k = 0; k < pass.Length; k++) {
                       pw_pad36[k] ^= pass[k ];
                    }

                    for (int k = 0; k < pass.Length; k++) {
                       pw_pad5C[k] ^= pass[k ];
                    }


                    var hash = new Hash();
                    hash.update32(pw_pad36);
                    hash.update(salt);
                    hash.update(ins);
                    var h = hash.finish();
                    
                    hash = new Hash();
                    hash.update32(pw_pad5C);
                    hash.update32(h);
                    h = hash.finish();
                
                    for (int k = 0; k < 32; k++) {
                       key[k] = h[k];
                    }

                    iter--;
                    while (iter-- > 0) {
                        hash = new Hash();

                        hash.update32(pw_pad36);
                        hash.update32(h);
                        h = hash.finish();

                        hash = new Hash();
                        hash.update32(pw_pad5C);
                        hash.update32(h);
                        h = hash.finish();

                        for (int k = 0; k < 32; k++)
                        {
                            key[k] ^= h[k];
                        }
                    }
                var gost = new Gost();
                gost.key(key);

                var  buf = gost.decrypt_cfb(iv, cryptdata);

                buf = Util.CopyArray(buf, 0, cryptdata.Length);

                 r = new AsnReader(new ReadOnlyMemory<byte>(buf), AsnEncodingRules.DER);
                 seq = r.ReadSequence();
                 seq.ReadInteger();
                 seq2 = seq.ReadSequence();
                 var param_d = seq.ReadOctetString();

                    seq2.ReadObjectIdentifier();

                    var priv = new Priv(param_d, seq2.ReadSequence(), true);
                 keys.Add(priv);


                }

            }
            catch (Exception)
            {

            }
            
         
            if (keys.Count == 0)
            {
                //try IIT 
                try
                {
                    var r = new AsnReader(new ReadOnlyMemory<byte>(_keydata), AsnEncodingRules.DER);
                    //var context = new Asn1Tag(TagClass.ContextSpecific, 0);

                    var sv = r.ReadSequence();
                    var p =sv.ReadSequence();
                    var oi = p.ReadObjectIdentifier();
                    if (oi != "1.3.6.1.4.1.19398.1.1.1.2")
                    {
                        throw new Exception("invalid keystore");
                    }

                    var mp = p.ReadSequence();

                    var mac = mp.ReadOctetString();
                    var pad = mp.ReadOctetString();

                    var crypddata = sv.ReadOctetString();


                    var pass =  Encoding.ASCII.GetBytes(password);

                    var hash = new Hash();
                    hash.update(pass);
                    var key =hash.finish();

                    int n = 10000;
                    n--;
                    while (0<n--) {
                      hash = new Hash();
                      hash.update32(key);
                      key = hash.finish();
                    }
                    var gost = new Gost();
                    gost.key(key);

                    var cbuf = Util.CopyArray(crypddata);

                    var buf = Util.MergeArray(cbuf, pad);
                    buf = gost.decrypt(buf);

                    buf = Util.CopyArray(buf, 0, cbuf.Length);
                    r = new AsnReader(new ReadOnlyMemory<byte>(buf), AsnEncodingRules.DER);
                    var seq = r.ReadSequence();
                    seq.ReadInteger();
                    var cp = seq.ReadSequence();
                    var t = cp.ReadObjectIdentifier();
                    var param_d = seq.ReadOctetString();

                    var priv = new Priv(param_d,cp.ReadSequence(),true);
                    keys.Add(priv);
                    var context = new Asn1Tag(TagClass.ContextSpecific, 0);

                    var attr = seq.ReadSequence(context);

                    AsnReader     cp2=null;
                    byte[] param_d2 = null;

                    while (attr.HasData)
                    {
                        var item = attr.ReadSequence();
                        
                        var ind = item.ReadObjectIdentifier();
                        if (ind == "1.3.6.1.4.1.19398.1.1.2.3")
                        {
                            int unu = 0;

                            param_d2 = item.ReadSetOf().ReadBitString(out unu);

                        }
                        if (ind == "1.3.6.1.4.1.19398.1.1.2.2")
                        {


                            cp2 = item.ReadSetOf().ReadSequence() ;
                            

                        }


                    }

                    var priv2 = new Priv(param_d2, cp2, true);
                    keys.Add(priv2);


                }
                catch (Exception)
                {

                }
            }


            var pb = cert.pub();
            foreach(var k in keys)
            {
                var kp = k.pub();

                if (pb.q.isequal(kp.q)){
                    return k;
                }
            }

            return null;
        }
        /// <summary>
        /// загрузка  и распаковка  jks (Приват банк)
        /// </summary>
        /// <param name="keydata">данные  файла  хранилища</param>
        /// <param name="password">Пароль</param>
        /// <returns>Возвращает  пару  ключ-сертификат</returns>
        public static JKSResult loadjks( byte[] keydata, string password)
        {

            var loader = new JKS(keydata, password);

            return loader.getData();

        }
    }


    internal  class JKS
    {
        private byte[] pass;
        private byte[] jksdata;
        private int pos = 0;
        private List<Cert>  certs = new List<Cert>() ;
        private List<Priv>  keys = new List<Priv>();

        public  JKS(byte[] jksdata, string password)
        {
            var pass = Encoding.ASCII.GetBytes(password);
            this.pass = Util.CopyArray(pass);
            this.jksdata = Util.CopyArray(jksdata);

            var test = this.U32();
            if(test  != 4277010157)
            {
                throw new Exception("Ivalid jks");
            }
            test = this.U32();
            if (test != 2)
            {
                throw new Exception("Ivalid jks");
            }
            var entries = this.U32();

            for (int i = 0; i < entries; i++) {
                var tag = this.U32();
                if (tag == 1) {
                  this.readKey();
                }
                if (tag == 2) {
                   var b = this.readCert();
                   this.certs.Add(new Cert(b));
                }
            }

        }



        public JKSResult getData()
        {
            //сравниваем  публичные  ключи
            foreach (var key in  this.keys ){
                var pubk = key.pub();
                foreach ( var cert in  this.certs ){
                    if (!cert.isKeyUsage) continue;
                    
                    var cpub = cert.pub();
                    if (pubk.q.isequal(cpub.q)) {


                        return new JKSResult(key,cert);
                        
                    }

                }
            }

            return null;
        }
        private byte[]   readCert()
        {
            var type = this.BIN(this.U16());
            var typename = Encoding.ASCII.GetString(type);
            var  data = this.BIN((int)this.U32());


            if (typename == "X.509")
            {
                return  data;
            }

            return null;
        }

        private void readKey()
        {
            this.BIN(this.U16());
            this.U32(); // skip timestamp high
            this.U32(); // skip timestamp low
            var key_data = this.BIN((int)this.U32());
            key_data = Util.CopyArray(key_data,0x18, key_data.Length - 0x18);
            var dk = this.decode(key_data);
            var r = new AsnReader(new ReadOnlyMemory<byte>(dk), AsnEncodingRules.DER);
            var seq = r.ReadSequence();
            seq.ReadInteger();
            var seq2 = seq.ReadSequence();
            var param_d = seq.ReadOctetString();
            var oi =seq2.ReadObjectIdentifier();

            var cp = seq2.ReadSequence();
            var t = cp.PeekTag();



            var priv = new Priv(param_d, cp, true);
            keys.Add(priv);
        
            var chain = this.U32();

            for (int i = 0; i < chain; i++) {
                var cd = this.readCert();
                if (cd != null) {
                    this.certs.Add( new Cert(cd));
                }
                
            }

        }

        private byte[] decode(byte[] key_data)
        {
            var pw = new byte[2*(this.pass.Length-1)+2];
            for (int i = 0; i < this.pass.Length; i++) {
                var code = pass[i];
                pw[i * 2] = (byte)(( code & 0xFF00) >> 8);
                pw[(i * 2) + 1] = (byte)( code & 0xFF);
            }


            var data =Util.CopyArray(key_data, 20, key_data.Length - 40);
            var iv = Util.CopyArray(key_data, 0, 20);
            var check = Util.CopyArray(key_data, key_data.Length - 20,20);
            var cur = Util.CopyArray(iv);

            var length = data.Length;

            byte[] open = new byte[length] ;

            int pos = 0;

            while (pos < length) {

                var h = Util.MergeArray(pw,cur);

                using (SHA1Managed sha1 = new SHA1Managed())
                {
                    cur = sha1.ComputeHash(h);
                }


                for (int i = 0; i < cur.Length; i++) {
                  open[pos] = (byte)(data[pos] ^ cur[i]);
                  pos++;
                   if (pos == open.Length) break;
                }
            }

          //  open = Util.CopyArray(open, 0, length);
 
            var h2 = Util.MergeArray(pw,open);
            byte[] digest;
            using (SHA1Managed sha1 = new SHA1Managed())
            {
                digest = sha1.ComputeHash(h2);
            }

            //проверка
            for (int i = 0; i < check.Length; i++) {
                if (digest[i] != check[i]) {
                    throw new Exception("Invalid jks key or password");
                };
            }

            return open;
        }
        private long U32()
        {

           var ret = (uint) (this.jksdata[this.pos] * 0x1000000 ) +
                (this.jksdata[this.pos + 1] << 16 ) +
                (this.jksdata[this.pos + 2] << 8 ) +
                (this.jksdata[this.pos + 3] );

            this.pos += 4;
            return ret;
        }

        private int  U16()
        {

            var ret = (this.jksdata[this.pos] << 8 ) |
                (this.jksdata[this.pos + 1] );

            this.pos += 2;
            return ret;
        }

        private byte[] BIN(int len)
        {

          var  ret = Util.CopyArray (this.jksdata, this.pos, len);

            this.pos += len;
            return ret;
        }
 
    }


    /// <summary>
    /// пара  ключ  сертификат
    /// 
    /// </summary>

    public class  JKSResult
    {
        public  Priv key { get; }
        public Cert cert { get; }

        public JKSResult(Priv key,Cert cert)
        {
            this.key = key;
            this.cert = cert;
        }
    }
}
