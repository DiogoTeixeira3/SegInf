package ex6;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;


public class ex6 {

    public static void sign(String filePath, String hashFlag, String keystorePath, String keystorePassword, String keyAlias)
            throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException,
            UnrecoverableKeyException, InvalidKeyException, SignatureException {

        //----------------Selecionar o algoritmo de assinatura (SHA1withRSA|SHA256withRSA)----------------//
        String digest = normalizeHash(hashFlag);              // "SHA1" | "SHA256"
        String sigAlg = digest + "withRSA";                   // "SHA256withRSA"

        //----------------Carregar o KeyStore (JKS)----------------//
        KeyStore ks = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(keystorePath)) {
            ks.load(fis, keystorePassword.toCharArray());
        }

        //----------------Obter a chave privada RSA do alias e validar----------------//
        Key key = ks.getKey(keyAlias, keystorePassword.toCharArray());
        if (!(key instanceof PrivateKey)) {
            throw new KeyStoreException("Chave privada não encontrada para o alias: " + keyAlias);
        }
        PrivateKey privateKey = (PrivateKey) key;
        if (!"RSA".equalsIgnoreCase(privateKey.getAlgorithm())) {
            throw new InvalidKeyException("A chave não é RSA.");
        }

        //----------------Criar e inicializar o objeto Signature com a chave privada----------------//
        Signature signature = Signature.getInstance(sigAlg);
        signature.initSign(privateKey, new SecureRandom());


        //----------------Ler ficheiro e atualizar sign----------------//
        // Leitura em streaming
        Path path = Path.of(filePath);
        try (InputStream is = Files.newInputStream(path)) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = is.read(buf)) > 0) {
                signature.update(buf, 0, n);
            }
        }

        //----------------Gerar a assinatura e gravá\-la em ficheiro----------------//
        byte[] digitalSignature = signature.sign();
        Files.write(Path.of(filePath + ".sig"), digitalSignature);
    }

    // Verifica a assinatura de `filePath` com o certificado `certPath` e a assinatura `sigPath`
    public static boolean verify(String filePath, String sigPath, String certPath, String hashFlag)
            throws IOException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {

        String digest = normalizeHash(hashFlag);
        String sigAlg = digest + "withRSA";

        // Carrega certificado X.509 (PEM ou DER)
        X509Certificate cert;
        try (InputStream in = new FileInputStream(certPath)) {
            cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        }

        if (!"RSA".equalsIgnoreCase(cert.getPublicKey().getAlgorithm())) {
            throw new InvalidKeyException("A chave pública do certificado não é RSA.");
        }

        Signature signature = Signature.getInstance(sigAlg);
        signature.initVerify(cert.getPublicKey());

        try (InputStream is = Files.newInputStream(Path.of(filePath))) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = is.read(buf)) > 0) {
                signature.update(buf, 0, n);
            }
        }

        byte[] sigBytes = Files.readAllBytes(Path.of(sigPath));
        return signature.verify(sigBytes);
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
        System.err.println("  -verify <-sha1|-sha256> <ficheiro> <ficheiro.sig> <certificado.cer|pem|der>");
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
                    if (args.length != 5) { usage(); return; }
                    boolean ok = verify(args[2], args[3], args[4], args[1]);
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
