Библиотека  для  цифровой подписи документов, отправляемых в  налоговую (Украина)

Большинство  кода  портировано с [https://github.com/dstucrypt/jkurwa](https://github.com/dstucrypt/jkurwa)   


Как  использовать

using DSTUSign;

Распаковка  ключа  и сертификата
   
   var cert = new Cert(File.ReadAllBytes("cert.cer"));
   var pk = KeyStore.load(File.ReadAllBytes("key-6.dat"), "password", cert);

   
   Распаковка на  слаых устройстваъ моэет  занять некоторое время, 
   в таком  случае обьекты  cert и key  следует 
   положить  в  сессию  или  сериализовать  и спрятать в  надежном  хранилище для дальнейшего использования
   
   
   Загрузка  jks файла (ПриватБанк)
    KeyStore::loadjks((File.ReadAllBytes("key.jks"),"password") ;
   
  
   
   Подпись  документа  или сообщения
   
   var text = "{ \"Command\":\"Objects\" }";
   var signed = Signer.sign( Encoding.UTF8.GetBytes(text), pk, cert)

   var signed = Signer.sign( File.ReadAllBytes("data.pdf"), pk, cert)

   проверка  подписи
   var isOK = Signer.check(signed);

   извлечение  данных из  подписанного  сообщения. 
   var data =  Signer.decrypt(signed);
 

  на  слабых устройставах  проверка  подписи  может  занять  время. 
  В случае надежного источника  сообщения достаточно  просто  вынуть  данные 

   
