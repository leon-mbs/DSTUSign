
## Библиотека  для  цифровой подписи документов (Украина) для .NET 


Большинство  кода  портировано с [https://github.com/dstucrypt/jkurwa](https://github.com/dstucrypt/jkurwa)     
Библиотека  не  использует сторонние или легаси библиотеки поэтому  легко портируется  на core.net  

Как  использовать

**using DSTUSign;**

Распаковка  ключа  и сертификата
   
   **var cert = new Cert(File.ReadAllBytes("cert.cer"));**  
   **var pk = KeyStore.load(File.ReadAllBytes("key-6.dat"), "password", cert);**

   
   Распаковка на  слабых устройстваъ может  занять некоторое время, 
   в таком  случае обьекты  cert и key  следует 
   положить  в  сессию  или  сериализовать  и спрятать в  надежном  хранилище для дальнейшего использования
     
   Из объекта  сертификата  можно  получить некоторые данные  о сертификате - серийный  номер, кто  выдал  и т.д.     
   
   Загрузка  jks файла (ПриватБанк)  
   **var keycert = KeyStore::loadjks((File.ReadAllBytes("key.jks"),"password") ;**
   
  
   
   Подпись  документа  или сообщения
   
   **var text = "{ \"Command\":\"Objects\" }";**  
   **var signed = Signer.sign( Encoding.UTF8.GetBytes(text), pk, cert);**  
   или    
   **var signed = Signer.sign( File.ReadAllBytes("data.pdf"), pk, cert);**

   Проверка  подписи  
   **var isOK = Signer.check(signed);**   

   Извлечение  данных из  подписанного  сообщения.   
   **var data =  Signer.decrypt(signed);**  
 

  На  слабых устройставах  проверка  подписи  может  занять  время. 
  В случае надежного источника  сообщения достаточно  просто  вынуть  данные 

   
