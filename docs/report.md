1.1 -
Neste processo, para proteger o ficheiro são aplicadas duas operações:
(1) Encriptação simétrica com AES-128-CBC. O modo CBC utiliza um IV (vetor de inicialização) que deve ser único e não repetido. O primeiro bloco da mensagem é combinado (XOR) com o IV antes de ser cifrado, e os blocos seguintes são combinados com o bloco cifrado anterior.
(2) Autenticação com HMAC-SHA256. O HMAC é calculado sobre o ficheiro original (f) com uma chave secreta. Este valor (tag h) é depois concatenado ao ficheiro cifrado (g), resultando no ficheiro final result.
No processo inverso, o destinatário pode recalcular o HMAC sobre f e comparar com a tag recebida para verificar a integridade e autenticidade.
Podemos afirmar portanto que estamos perante um Encrypth-then-Mac , onde realizamos numa fase inicial a cifra do ficheiro e consequentemente calculamos a tag deste ficheiro cifrado, concatenando o resultado da tag ao ficheiro cifrado. Desta forma podemos verificar se houve ou não uma alteração no ficheiro cifrado. E(k)(m) || T(k)(E(k)(m))


1.2-
Neste caso estamos a comparar dois modos de cifra: CBC (Cipher Block Chaining) e CTR (Counter).
CBC: cada bloco depende do anterior. Um erro num bloco cifrado afeta esse bloco ao descifrar e também introduz erros no bloco seguinte. Como há dependência entre blocos, não é possível decifrar em paralelo nem ordenar blocos.

CTR: funciona como um modo de fluxo, gerando um keystream a partir de um contador. Cada bloco pode ser cifrado/decifrado de forma independente, permitindo paralelismo. Erros num bloco cifrado só afetam esse bloco, sem propagação para os seguintes. Isso porque cada bit do criptograma corresponde apenas a um bit do texto plano e o fluxo de chave é gerado independentemente do criptograma.


1.3-
Para realizar a verificação do ficheiro, começamos por separar result em g (ficheiro cifrado) e h (HMAC) .De seguida, calcula-se novamente o HMAC-SHA256 sobre o ficheiro cifrado g usando a mesma chave secreta, obtendo 'h'. Se coincidir com a tag recebida, o criptograma é considerado autêntico e íntegro, podendo então ser decifrado com AES-128-CBC, utilizando a mesma chave e IV, para recuperar o ficheiro original f.
Caso contrário, o ficheiro é rejeitado, pois indica alteração ou corrupção do conteúdo.

2. Para realizar a implementação desta comunicação , temos de seguir os seguintes passos:

1- Primeiro precisamos de gerar o par de chaves pública e privada para as operações de cifra e decifra respetivamente, fazendo isto com o seguinte comando:

openssl genrsa -out bob_private_key.pem 2048

tendo em conta que o bob_private_key.pem é o ficheiro que deve ser gerado com a chave privada e 2048 o numero de bits do mesmo.
Uma vez a geração do ficheiro feita , podemos então realizar a extração da chave publica do mesmo com o comando:

openssl rsa -in bob_private_key.pem -out bob_public_key.pem -pubout

2- Uma vez gerado ambas as chaves, o proximo passo é realizar a função de hash SHA-256 sobre a mensagem de texto que é suposto transmitir sobre o canal de comunicação, realizando o comando:

openssl dgst -sha256 message.txt > message.hash
Assumindo que a mensagem que queremos enviar está em mensagem.txt, isto vai gerar portanto um ficheiro message.hash que contém o resultado da função de hash aplicada sobre o ficheiro message.txt

3- Próximo passo é cifrar o ficheiro da mensagem utilizando a chave publica previamente gerado , utilizando este comando:


openssl pkeyutl -encrypt -inkey bob_public_key.pem -pubin -in message.txt -out message.enc

gerando portanto o ficheiro message.enc que contém a mensagem cifrada utilizada a chave publica especificada em -inkey

4- O ultimo passo antes de enviar a mensagem é concatenar o ficheiro cifrado com o ficheiro resultante da função de hash:
copy /b message.enc + message.hash result.bin

sendo que o result.bin contém portanto o resultado de E(k)(m) || sha-256(m)

Isto são os comandos necessários para fazer a implementação do envio, para fazer a receção e validação da informação temos que:


1- dividir os ficheiros em parte cifrada e parte que corresponde ao hash assumindo que temos conhecimento do tamanho cifrado

2- utilizando a chave privada gerada , decifrar o ficheiro recebido com o comando:


openssl pkeyutl -decrypt -inkey bob_private_key.pem -in received.enc -out decrypted_message.txt

assumindo que o received.enc é a parte cifrada do ficheiro recebido após divisão entre ficheiro cifrado e respetivo hash.

3- Por fim , basta apenas calcular o hash da mensagem decifrada utilizando a mesma função de hash , neste caso , sha-256 e comparar o resultado obtido com o recebido.
openssl dgst -sha256 decrypted_message.txt > decrypted_message.hash




2.2 Este esquema garante confidencialidade , ou seja previne a divulgação não autorizada de informação , impedindo que atacantes consigam ler a mensagem.
No entanto, não assegura integridade nem autenticidade, isto porque apenas se calcula uma função de  hash SHA-256 simples da mensagem original.
Como o SHA-256 não utiliza uma chave privada, um atacante pode criar uma mensagem diferente e gerar o seu próprio hash, mantendo a confidencialidade do conteúdo original mas comprometendo a integridade e a autenticidade da comunicação.
Uma possível solução para garantir tanto confidencialidade como integridade e autenticidade é utilizar um esquema híbrido, combinando esquemas simétricos e assimétricos. Neste esquema a mensagem é cifrada usando uma chave simétrica K, de seguida ,essa chave vai ser cifrada usando a chave pública do destinatário (RSA), garantindo que apenas o destinatário com a chave privada correspondente consegue decifrar K.
Para verificar integridade e autenticidade, podemos calcular um HMAC com K antes da transmissão.
Desta forma, apenas o destinatário autorizado consegue decifrar a chave simétrica e, em seguida, verificar a autenticidade e integridade da mensagem, garantindo confidencialidade, integridade e, dependendo do modo escolhido, autenticidade.


3.

3.1 -



3.2
O algoritmo utilizado para produzir a assinatura do certificado está presente no nome , sendo portanto o TLS ECC SHA384  utilizando portanto o ECDSA com a função de hash sha384 e se quisessem verificar isso pelo openssl bastava fazer o seguinte:




openssl x509 -in cert.crt -text -noout
sendo o cert.crt o nome do certificado depois de baixado , iria gerar um ficheiro com as seguintes informações:

Certificate:
Data:
Version: 3 (0x2)
Serial Number:
0b:00:e9:2d:4d:6d:73:1f:ca:30:59:c7:cb:1e:18:86
Signature Algorithm: ecdsa-with-SHA384
Issuer: C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Global Root G3
Validity
Not Before: Apr 14 00:00:00 2021 GMT
Not After : Apr 13 23:59:59 2031 GMT
Subject: C=US, O=DigiCert Inc, CN=DigiCert Global G3 TLS ECC SHA384 2020 CA1
Subject Public Key Info:
Public Key Algorithm: id-ecPublicKey
Public-Key: (384 bit)
pub:
04:78:a9:9c:75:ae:88:5d:63:a4:ad:5d:86:d8:10:
49:d6:af:92:59:63:43:23:85:f4:48:65:30:cd:4a:
34:95:a6:0e:3e:d9:7c:08:d7:57:05:28:48:9e:0b:
ab:eb:c2:d3:96:9e:ed:45:d2:8b:8a:ce:01:4b:17:
43:e1:73:cf:6d:73:48:34:dc:00:46:09:b5:56:54:
c9:5f:7a:c7:13:07:d0:6c:18:17:6c:ca:db:c7:0b:
26:56:2e:8d:07:f5:67
ASN1 OID: secp384r1
NIST CURVE: P-384
X509v3 extensions:
X509v3 Basic Constraints: critical
CA:TRUE, pathlen:0
X509v3 Subject Key Identifier:
8A:23:EB:9E:6B:D7:F9:37:5D:F9:6D:21:39:76:9A:A1:67:DE:10:A8
X509v3 Authority Key Identifier:
B3:DB:48:A4:F9:A1:C5:D8:AE:36:41:CC:11:63:69:62:29:BC:4B:C6
X509v3 Key Usage: critical
Digital Signature, Certificate Sign, CRL Sign
X509v3 Extended Key Usage:
TLS Web Server Authentication, TLS Web Client Authentication
Authority Information Access:
OCSP - URI:http://ocsp.digicert.com
CA Issuers - URI:http://cacerts.digicert.com/DigiCertGlobalRootG3.crt
X509v3 CRL Distribution Points:
Full Name:
URI:http://crl3.digicert.com/DigiCertGlobalRootG3.crl

            X509v3 Certificate Policies:
                Policy: 2.16.840.1.114412.2.1
                Policy: 2.23.140.1.1
                Policy: 2.23.140.1.2.1
                Policy: 2.23.140.1.2.2
                Policy: 2.23.140.1.2.3
    Signature Algorithm: ecdsa-with-SHA384
    Signature Value:
        30:65:02:30:7e:26:58:6e:ee:88:ec:0c:dd:15:41:ee:7a:b8:
        99:99:70:d1:62:65:4f:a0:20:9e:47:b1:5b:c1:b2:67:31:1d:
        cc:72:7a:af:22:72:40:42:6e:65:84:fe:87:4b:0f:19:02:31:
        00:e6:bf:d6:ae:34:87:5b:3f:67:c7:1d:a8:6f:d5:12:78:b5:
        e6:87:31:44:a9:5d:c6:b8:78:cc:cf:ef:d4:32:58:11:ff:3a:
        85:06:3c:1d:84:6f:d3:f5:f9:da:33:1c:a4

Como podemos ver no Signature Alghorithm lá está o algoritmo de assinatura ecdsa-with-SHA384


























PARTE 2




4.2 - André Vaz
Intel i7 e sistema operativo Windows
exec1 = 0,479s
exec2 = 0,584s
exec3 = 0,491s
tempo médio = 0,518

4.3 - Se um ataque permitisse encontrar colisões em todos os 256 bits do SHA‑256, o uso desta função num esquema de assinatura digital teria consequências graves. 
Em particular, um atacante poderia gerar pares de mensagens m e m′ tais que SHA-256(m) = SHA-256(m′). 
Se o atacante convencer a vítima a assinar m, a assinatura resultante seria igualmente válida para m′, permitindo a falsificação de assinaturas. 
Assim, a autenticidade fica comprometida — não é possível garantir a entidade envolvida é quem diz ser  — e a integridade também é posta em causa, pois assinaturas válidas poderiam ser reutilizadas para documentos manipulados.

### 5.2 – Solução sem canal seguro para troca de chaves

Na alínea anterior, a chave simétrica `k` tinha de ser enviada por um canal seguro.  
Para eliminar essa necessidade, utiliza-se um **esquema híbrido**, combinando cifra simétrica e assimétrica:

1. O emissor gera uma **chave simétrica aleatória** `k` (ex.: AES-128).
2. Cifra a mensagem com **AES/CBC** e autentica com **HMAC-SHA256**:

   \[
   AE(k)(m) = E_k(m) \, || \, T_k(E_k(m))
   \]

3. Cifra a chave `k` com a **chave pública RSA** do recetor:

   \[
   k_{enc} = E_{RSA}(K_{pub}, k)
   \]

4. Envia ao recetor:

   \[
   k_{enc} \, || \, AE(k)(m)
   \]

5. O recetor usa a sua **chave privada RSA** para obter `k` e decifrar a mensagem.

A definição modificada torna-se:

\[
AE^{*}(K_{pub})(m) = E_{RSA}(K_{pub}, k) \, || \, E_k(m) \, || \, T_k(E_k(m))
\]

> 💡 Desta forma, já **não é necessário um canal seguro**, pois a chave simétrica é protegida pela chave pública do recetor.
