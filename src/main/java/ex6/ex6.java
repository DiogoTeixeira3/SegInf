package ex6;

import java.io.FileInputStream;    // para ler ficheiros (keystores, certificados, assinaturas)
import java.io.IOException;
import java.io.InputStream;        // para ler ficheiros em streaming
import java.nio.file.Files;       // utilitários para ficheiros (ler/escrever)
import java.nio.file.Path;        // representação de caminhos de ficheiro
import java.security.*;           // classes de segurança: KeyStore, Signature, PrivateKey, etc.
import java.security.cert.*;      // classes para certificados e validação de cadeias
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;


public class ex6 {

    // Método que assina um ficheiro com a chave privada contida num keystore PKCS12 (.pfx/.p12)
    public static void sign(String filePath, String hashFlag, String keystorePath, String keystorePassword, String keyAlias)
            throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException,
            UnrecoverableKeyException, InvalidKeyException, SignatureException {

        // === 1. Selecionar o algoritmo de assinatura ===
        // normalizeHash converte o flag (-sha1 ou -sha256) para "SHA1" ou "SHA256"
        String digest = normalizeHash(hashFlag);   // ex.: "-sha256" -> "SHA256"
        // Concatena para formar o identificador do Signature (ex.: "SHA256withRSA")
        String sigAlg = digest + "withRSA";

        // === 2. Carregar o keystore PKCS12 que contém a chave privada ===
        KeyStore ks = KeyStore.getInstance("PKCS12");
        // Abre o ficheiro do keystore e carrega-o com a password fornecida
        try (FileInputStream fis = new FileInputStream(keystorePath)) {
            ks.load(fis, keystorePassword.toCharArray());
        }

        // === 3. Obter a chave privada pelo alias ===
        Key key = ks.getKey(keyAlias, keystorePassword.toCharArray());
        // Verifica que a entrada do keystore é de facto uma chave privada
        if (!(key instanceof PrivateKey)) {
            throw new KeyStoreException("Chave privada não encontrada para o alias: " + keyAlias);
        }
        PrivateKey privateKey = (PrivateKey) key;

        // Confirma que a chave privada é do tipo RSA (o código assume RSA)
        if (!"RSA".equalsIgnoreCase(privateKey.getAlgorithm())) {
            throw new InvalidKeyException("A chave não é RSA.");
        }

        // === 4. Criar e inicializar o objeto Signature com o algoritmo escolhido ===
        Signature signature = Signature.getInstance(sigAlg);
        // Inicializa para assinatura com a chave privada e um SecureRandom para aleatoriedade
        signature.initSign(privateKey, new SecureRandom());

        // === 5. Ler o ficheiro a assinar em streaming e alimentar o objeto Signature ===
        Path path = Path.of(filePath);
        try (InputStream is = Files.newInputStream(path)) {
            byte[] buf = new byte[8192];  // buffer de leitura (8 KB)
            int n;
            while ((n = is.read(buf)) > 0) {
                // Atualiza o cálculo da assinatura com os bytes lidos
                signature.update(buf, 0, n);
            }
        }

        // === 6. Gerar a assinatura (opera sobre o hash interno com a chave privada) ===
        byte[] digitalSignature = signature.sign();

        // === 7. Guardar a assinatura num ficheiro com sufixo .sig ===
        Files.write(Path.of(filePath + ".sig"), digitalSignature);
    }

    // Método que verifica a assinatura de um ficheiro, e valida a cadeia de certificação fornecida
    public static boolean verify(String filePath, String signaturePath, String signerCertPath, String intermediateCertPath, String trustStorePath, String trustStorePassword) {
        try (FileInputStream fileIn = new FileInputStream(filePath);
             FileInputStream signatureIn = new FileInputStream(signaturePath)) {

            // 1. Ler o TrustStore (onde estão as CA's de root/trusted)
            KeyStore ts = KeyStore.getInstance("JKS");
            ts.load(new FileInputStream(trustStorePath), trustStorePassword.toCharArray());

            // 2. Ler os certificados que vamos usar para construir a cadeia
            CertificateFactory cf = CertificateFactory.getInstance("X.509");

            // Ler o certificado do signatário (end-entity), por exemplo Alice_1.cer
            Certificate signerCert = cf.generateCertificate(new FileInputStream(signerCertPath));

            // Ler o certificado intermédio (o que emite para o signatário): CA1-int.cer, por exemplo
            Certificate intermediateCert = cf.generateCertificate(new FileInputStream(intermediateCertPath));

            // 3. Construir a lista/cadeia de certificados na ordem esperada pelo CertPath:
            //    [end-entity, intermediate, ...] (a raiz fica no truststore)
            List<Certificate> certChainList = new java.util.ArrayList<>();
            certChainList.add(signerCert);
            certChainList.add(intermediateCert);

            // Gerar um CertPath a partir da lista
            CertPath certPath = cf.generateCertPath(certChainList);

            // 4. Validar a cadeia de certificação com CertPathValidator (PKIX)
            try {
                CertPathValidator cpv = CertPathValidator.getInstance("PKIX");
                // PKIXParameters usa o truststore (anchors/trusted CAs)
                PKIXParameters params = new PKIXParameters(ts);
                // Desliga verificação de revogação (CRL/OCSP) para simplificar o lab work
                params.setRevocationEnabled(false);
                // Valida o certPath; se falhar, lança CertPathValidatorException
                cpv.validate(certPath, params);
                System.out.println("A cadeia de certificação é válida.");
            } catch (java.security.cert.CertPathValidatorException e) {
                // Se a validação da cadeia falhar, mostra a mensagem e devolve false
                System.out.println("A validação da cadeia de certificação falhou: " + e.getMessage());
                return false;
            }

            // 5. Se a cadeia for válida, verificar a assinatura criptográfica do ficheiro
            Signature signature = Signature.getInstance("SHA256withRSA");
            // Inicializa o Signature em modo verify com a chave pública do signatário
            signature.initVerify(signerCert.getPublicKey());

            // Ler o ficheiro em streaming e atualizar o Signature
            byte[] buffer = new byte[8192];
            int n;
            while ((n = fileIn.read(buffer)) != -1) {
                signature.update(buffer, 0, n);
            }

            // Ler os bytes da assinatura do ficheiro .sig
            byte[] signatureBytes = signatureIn.readAllBytes();
            // Verificar se a assinatura corresponde; return true se OK, false caso contrário
            return signature.verify(signatureBytes);

        } catch (Exception e) {
            // Em caso de erro (I/O, keystore, algoritmo, etc.) mostra a stacktrace e devolve false
            System.err.println("Erro: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    // Converte o flag de entrada (-sha1 ou -sha256) para a string usada internamente ("SHA1" ou "SHA256")
    private static String normalizeHash(String flag) {
        if (flag == null) return "SHA256";                 // valor por defeito
        String f = flag.replace("-", "").toUpperCase();    // remove '-' e passa para maiúsculas
        if (f.equals("SHA1")) return "SHA1";
        if (f.equals("SHA256")) return "SHA256";
        throw new IllegalArgumentException("Hash inválido. Use `-sha1` ou `-sha256`.");
    }

    // Mensagem de ajuda/uso quando os argumentos são inválidos
    private static void usage() {
        System.err.println("Uso:");
        System.err.println("  -sign   <-sha1|-sha256> <ficheiro> <keystore.jks> <password> <alias>");
        System.err.println("  -verify <-sha1|-sha256> <ficheiro> <ficheiro.sig> <certificado.cer> <truststore.jks> <password>");
    }

    // Ponto de entrada da aplicação: parse simples dos argumentos e chamada a sign/verify
    public static void main(String[] args) {
        if (args.length == 0) { usage(); return; }
        try {
            switch (args[0]) {
                case "-sign":
                    // Expect exactly 6 args: -sign <hash> <file> <keystore> <password> <alias>
                    if (args.length != 6) { usage(); return; }
                    // Chama sign com a ordem definida no teu programa
                    sign(args[2], args[1], args[3], args[4], args[5]);
                    System.out.println("Assinatura gerada em: " + args[2] + ".sig");
                    break;
                case "-verify":
                    // Expect exactly 8 args: -verify <hash> <file> <sig> <cert> <interm> <truststore> <pass>
                    if (args.length != 8) {
                        usage();
                        return;
                    }
                    // Chama verify com os argumentos apropriados (verifica cadeia + assinatura)
                    boolean ok = verify(args[2], args[3], args[4], args[5], args[6], args[7]);
                    System.out.println(ok ? "Assinatura válida" : "Assinatura inválida");
                    break;
                default:
                    usage();
            }
        } catch (Exception e) {
            // Se ocorrer qualquer exceção durante sign/verify, imprime mensagem curta
            System.err.println("Erro: " + e.getMessage());
        }
    }
}