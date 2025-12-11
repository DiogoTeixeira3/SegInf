package ex6;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;


public class ex6 {

    public static void sign(String filePath, String hashFlag, String keystorePath, String keystorePassword, String keyAlias)
            throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException,
            UnrecoverableKeyException, InvalidKeyException, SignatureException {

        // === 1. Selecionar o algoritmo de assinatura ===
        // A assinatura digital é uma combinação de uma função de hash com um algoritmo assimétrico.
        // Exemplo: SHA256withRSA → primeiro aplica SHA-256 ao ficheiro e depois cifra o hash com a chave privada RSA.
        String digest = normalizeHash(hashFlag);   // Converte "-sha1" → "SHA1", "-sha256" → "SHA256"
        String sigAlg = digest + "withRSA";        // Forma final do algoritmo: "SHA256withRSA"

        // === 2. Carregar o keystore que contém a chave privada ===
        // Cria um objeto KeyStore do tipo PKCS12 (formato moderno e compatível com .p12/.pfx)
        KeyStore ks = KeyStore.getInstance("PKCS12");

        // Abre o ficheiro e carrega o keystore na memória, usando a password indicada
        // Lê de um ficheiro e carrega
        try (FileInputStream fis = new FileInputStream(keystorePath)) {
            ks.load(fis, keystorePassword.toCharArray());
        }

        // === 3. Obter a chave privada associada ao alias indicado ===
        // A chave será usada para gerar a assinatura.
        // Sacar a key
        Key key = ks.getKey(keyAlias, keystorePassword.toCharArray());

        // Verifica se o alias contém de facto uma chave privada
        if (!(key instanceof PrivateKey)) {
            throw new KeyStoreException("Chave privada não encontrada para o alias: " + keyAlias);
        }

        PrivateKey privateKey = (PrivateKey) key;

        // Confirma que a chave é RSA, pois outros tipos (ex: EC) não são suportados aqui
        if (!"RSA".equalsIgnoreCase(privateKey.getAlgorithm())) {
            throw new InvalidKeyException("A chave não é RSA.");
        }

        // === 4. Criar e inicializar o objeto Signature ===
        // A classe Signature combina o algoritmo de hash e a operação de cifra da assinatura.
        // Cria um objeto em que especificas o algoritmo
        Signature signature = Signature.getInstance(sigAlg);

        // Inicializa o objeto em modo "sign" com a chave privada e um gerador de aleatoriedade seguro.
        // Assina e faz o hash
        signature.initSign(privateKey, new SecureRandom());

        // === 5. Ler o ficheiro e atualizar o cálculo da assinatura ===
        // O ficheiro é processado em blocos (streaming) para suportar ficheiros grandes.
        // Calcula o hash
        Path path = Path.of(filePath);
        try (InputStream is = Files.newInputStream(path)) {
            byte[] buf = new byte[8192];  // buffer de 8 KB
            int n;
            while ((n = is.read(buf)) > 0) {
                // Para cada bloco lido, atualiza o objeto Signature com esses bytes
                signature.update(buf, 0, n);
            }
        }

        // === 6. Gerar a assinatura digital ===
        // Neste momento, o hash completo já foi calculado internamente;
        // a função sign() aplica a operação RSA sobre o hash.
        byte[] digitalSignature = signature.sign();

        // === 7. Guardar a assinatura em ficheiro ===
        // A assinatura resultante (em binário) é escrita num novo ficheiro com o mesmo nome + ".sig"
        Files.write(Path.of(filePath + ".sig"), digitalSignature);
    }

    // Verifica a assinatura de `filePath` com o certificado `certPath` e a assinatura `sigPath`
    public static boolean verify(String filePath, String signaturePath, String signerCertPath, String intermediateCertPath, String trustStorePath, String trustStorePassword) {
        try (FileInputStream fileIn = new FileInputStream(filePath);
             FileInputStream signatureIn = new FileInputStream(signaturePath)) {

            // 1. Ler o TrustStore
            KeyStore ts = KeyStore.getInstance("JKS");
            ts.load(new FileInputStream(trustStorePath), trustStorePassword.toCharArray());

            // 2. Ler os certificados para construir a cadeia
            CertificateFactory cf = CertificateFactory.getInstance("X.509");

            // Ler o certificado do signatário (Alice)
            Certificate signerCert = cf.generateCertificate(new FileInputStream(signerCertPath));

            // Ler o certificado da CA Intermédia
            Certificate intermediateCert = cf.generateCertificate(new FileInputStream(intermediateCertPath));

            // Construir a cadeia de certificação: [signatário, intermédia]
            List<Certificate> certChainList = new java.util.ArrayList<>();
            certChainList.add(signerCert);
            certChainList.add(intermediateCert);

            CertPath certPath = cf.generateCertPath(certChainList);

            // 3. Validar a cadeia de certificação
            try {
                CertPathValidator cpv = CertPathValidator.getInstance("PKIX");
                PKIXParameters params = new PKIXParameters(ts);
                params.setRevocationEnabled(false); // Simplificação para o trabalho
                cpv.validate(certPath, params);
                System.out.println("A cadeia de certificação é válida.");
            } catch (java.security.cert.CertPathValidatorException e) {
                System.out.println("A validação da cadeia de certificação falhou: " + e.getMessage());
                return false;
            }

            // 4. Se a cadeia for válida, verificar a assinatura
            Signature signature = Signature.getInstance("SHA256withRSA"); // Assumindo SHA256
            signature.initVerify(signerCert.getPublicKey());

            byte[] buffer = new byte[8192];
            int n;
            while ((n = fileIn.read(buffer)) != -1) {
                signature.update(buffer, 0, n);
            }

            byte[] signatureBytes = signatureIn.readAllBytes();
            return signature.verify(signatureBytes);

        } catch (Exception e) {
            System.err.println("Erro: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    private static String normalizeHash(String flag) {
        if (flag == null) return "SHA256";
        String f = flag.replace("-", "").toUpperCase();
        if (f.equals("SHA1")) return "SHA1";
        if (f.equals("SHA256")) return "SHA256";
        throw new IllegalArgumentException("Hash inválido. Use `-sha1` ou `-sha256`.");
    }

    private static void usage() {
        System.err.println("Uso:");
        System.err.println("  -sign   <-sha1|-sha256> <ficheiro> <keystore.jks> <password> <alias>");
        System.err.println("  -verify <-sha1|-sha256> <ficheiro> <ficheiro.sig> <certificado.cer> <truststore.jks> <password>");
    }

    public static void main(String[] args) {
        if (args.length == 0) { usage(); return; }
        try {
            switch (args[0]) {
                case "-sign":
                    if (args.length != 6) { usage(); return; }
                    sign(args[2], args[1], args[3], args[4], args[5]);
                    System.out.println("Assinatura gerada em: " + args[2] + ".sig");
                    break;
                case "-verify":
                    // 7 argumentos: -verify, -sha256, file, sig, cert, interm-cert, truststore, pass
                    if (args.length != 8) {
                        usage();
                        return;
                    }
                    // ndices dos argumentos: 2, 3, 4, 5, 6, 7
                    boolean ok = verify(args[2], args[3], args[4], args[5], args[6], args[7]);
                    System.out.println(ok ? "Assinatura válida" : "Assinatura inválida");
                    break;
                default:
                    usage();
            }
        } catch (Exception e) {
            System.err.println("Erro: " + e.getMessage());
        }
    }
}