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

        // Selecionar o algoritmo de assinatura (SHA1withRSA|SHA256withRSA)
        String digest = normalizeHash(hashFlag);              // "SHA1" | "SHA256"
        String sigAlg = digest + "withRSA";                   // "SHA256withRSA"

        // Carregar o KeyStore (JKS)
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(keystorePath)) {
            ks.load(fis, keystorePassword.toCharArray());
        }

        // Obter a chave privada RSA do alias e validar
        Key key = ks.getKey(keyAlias, keystorePassword.toCharArray());
        if (!(key instanceof PrivateKey)) {
            throw new KeyStoreException("Chave privada não encontrada para o alias: " + keyAlias);
        }

        PrivateKey privateKey = (PrivateKey) key;
        if (!"RSA".equalsIgnoreCase(privateKey.getAlgorithm())) {
            throw new InvalidKeyException("A chave não é RSA.");
        }

        // Criar e inicializar o objeto Signature com a chave privada
        Signature signature = Signature.getInstance(sigAlg);
        signature.initSign(privateKey, new SecureRandom());


        // Ler ficheiro e atualizar sign
        // Leitura em streaming
        Path path = Path.of(filePath);
        try (InputStream is = Files.newInputStream(path)) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = is.read(buf)) > 0) {
                signature.update(buf, 0, n);
            }
        }

        // Gerar a assinatura e gravá-la em ficheiro
        byte[] digitalSignature = signature.sign();
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