package ex5;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.util.Base64;

public class ex5 {

    // Constantes para os algoritmos
    private static final String CIPHER_ALG = "AES/CBC/PKCS5Padding"; // Algoritmo de cifra simétrica
    private static final String MAC_ALG = "HmacSHA256";             // Algoritmo de autenticação (MAC)
    private static final int IV_SIZE = 16;                          // Tamanho do Vetor de Inicialização (IV) para AES (128 bits)

    //ALÍNEA 5.1 (CHAVE PRÉ-PARTILHADA)

    /**
     * [5.1] Gera uma chave AES de 128 bits e guarda-a num ficheiro.
     */
    public static void generateKey(String keyFilePath) throws NoSuchAlgorithmException, IOException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey secretKey = keyGen.generateKey();
        Files.write(Path.of(keyFilePath), secretKey.getEncoded());
        System.out.println("Chave aleatória gerada e guardada em: " + keyFilePath);
    }

    /**
     * [5.1] Cifra um ficheiro usando o esquema Encrypt-then-MAC com chave pré-partilhada.
     * O resultado final (IV + Cifrado + MAC) é codificado em Base64.
     */
    public static void cipher(String inputFilePath, String outputFilePath, String keyFilePath)
            throws GeneralSecurityException, IOException {

        // Carrega a chave partilhada do ficheiro.
        byte[] keyBytes = Files.readAllBytes(Path.of(keyFilePath));
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");

        // Prepara a cifra AES e o MAC com a mesma chave.
        Cipher cipher = Cipher.getInstance(CIPHER_ALG);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] iv = cipher.getIV();

        Mac mac = Mac.getInstance(MAC_ALG);
        mac.init(secretKey);
        mac.update(iv); // O MAC também protege o IV.

        // Usa streams para cifrar, calcular MAC e codificar em Base64, tudo de uma vez.
        try (
                InputStream in = new FileInputStream(inputFilePath);
                FileOutputStream fos = new FileOutputStream(outputFilePath);
                OutputStream base64Out = Base64.getEncoder().wrap(fos);
                MacUpdatingOutputStream macOut = new MacUpdatingOutputStream(base64Out, mac);
                CipherOutputStream cos = new CipherOutputStream(macOut, cipher)
        ) {
            base64Out.write(iv);
            in.transferTo(cos); // Os dados fluem do ficheiro -> cifra -> mac -> base64 -> ficheiro de saída.
        }

        // Finaliza o MAC e anexa-o ao final do ficheiro.
        byte[] macTag = mac.doFinal();
        try (OutputStream fos = new FileOutputStream(outputFilePath, true)) {
            fos.write(Base64.getEncoder().encode(macTag));
        }

        System.out.println("Ficheiro cifrado e guardado em: " + outputFilePath);
    }

    /**
     * [5.1] Decifra e verifica um ficheiro protegido com chave pré-partilhada.
     */
    public static boolean decipher(String inputFilePath, String outputFilePath, String keyFilePath)
            throws GeneralSecurityException, IOException {
        // Carrega a chave partilhada.
        byte[] keyBytes = Files.readAllBytes(Path.of(keyFilePath));
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");

        // Prepara o MAC para verificação.
        Mac mac = Mac.getInstance(MAC_ALG);
        mac.init(secretKey);

        // Descodifica o ficheiro Base64 para a memória para separar as partes.
        byte[] decodedBytes;
        try (InputStream in = Base64.getDecoder().wrap(new FileInputStream(inputFilePath))) {
            decodedBytes = in.readAllBytes();
        }

        // Separa o IV, a tag MAC recebida e os dados cifrados.
        byte[] iv = Arrays.copyOfRange(decodedBytes, 0, IV_SIZE);
        byte[] macTagReceived = Arrays.copyOfRange(decodedBytes, decodedBytes.length - mac.getMacLength(), decodedBytes.length);
        byte[] encryptedData = Arrays.copyOfRange(decodedBytes, IV_SIZE, decodedBytes.length - mac.getMacLength());

        // Calcula o MAC esperado sobre os dados recebidos.
        mac.update(iv);
        mac.update(encryptedData);
        byte[] macTagCalculated = mac.doFinal();

        // Compara a tag recebida com a calculada de forma segura. Se forem diferentes, a mensagem foi alterada.
        if (!MessageDigest.isEqual(macTagReceived, macTagCalculated)) {
            return false;
        }

        // A mensagem é autêntica. Procede à decifra.
        Cipher cipher = Cipher.getInstance(CIPHER_ALG);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));

        try (OutputStream out = new FileOutputStream(outputFilePath)) {
            out.write(cipher.doFinal(encryptedData));
        }

        return true;
    }


    // ALÍNEA 5.2 (CRIPTO-SISTEMA HÍBRIDO)
    /**
     * [5.2] Cifra um ficheiro usando um esquema híbrido (envelope digital).
     * Não usa Base64, pois o formato binário é mais eficiente e direto.
     */
    public static void cipherHybrid(String inputFilePath, String outputFilePath, String recipientCertPath)
            throws GeneralSecurityException, IOException {

        // Gera uma chave de sessão AES aleatória para uso único.
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey sessionKey = keyGen.generateKey();

        // Carrega o certificado do destinatário para obter a sua chave pública.
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate recipientCert = cf.generateCertificate(new FileInputStream(recipientCertPath));
        PublicKey recipientPublicKey = recipientCert.getPublicKey();

        // Cifra (embrulha) a chave de sessão com a chave pública RSA do destinatário.
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.WRAP_MODE, recipientPublicKey);
        byte[] wrappedSessionKey = rsaCipher.wrap(sessionKey);

        // Prepara a cifra AES para o conteúdo do ficheiro.
        Cipher aesCipher = Cipher.getInstance(CIPHER_ALG);
        aesCipher.init(Cipher.ENCRYPT_MODE, sessionKey);
        byte[] iv = aesCipher.getIV();

        // Prepara o MAC para garantir a autenticidade.
        Mac mac = Mac.getInstance(MAC_ALG);
        mac.init(sessionKey);
        mac.update(iv);

        // Escreve para o ficheiro de saída num formato estruturado:
        // [comprimento da chave cifrada] [chave cifrada] [IV] [dados cifrados]
        try (
                FileOutputStream fos = new FileOutputStream(outputFilePath);
                DataOutputStream dos = new DataOutputStream(fos); // Ajuda a escrever tipos de dados (int)
                InputStream in = new FileInputStream(inputFilePath)
        ) {
            // Escreve o tamanho da chave embrulhada, para que o 'decipher' saiba o que ler.
            dos.writeInt(wrappedSessionKey.length);
            dos.write(wrappedSessionKey);
            dos.write(iv);

            // Cifra e calcula o MAC em streaming.
            try (MacUpdatingOutputStream macOut = new MacUpdatingOutputStream(dos, mac);
                 CipherOutputStream cos = new CipherOutputStream(macOut, aesCipher)) {
                in.transferTo(cos);
            }
        }

        // Anexa a tag MAC no final do ficheiro.
        byte[] macTag = mac.doFinal();
        try (OutputStream fos = new FileOutputStream(outputFilePath, true)) { // true = modo append
            fos.write(macTag);
        }

        System.out.println("Ficheiro cifrado com envelope digital e guardado em: " + outputFilePath);
    }


    /**
     * [5.2] Decifra um ficheiro protegido com envelope digital.
     */
    public static boolean decipherHybrid(String inputFilePath, String outputFilePath, String privateKeystorePath, String keystorePassword)
            throws GeneralSecurityException, IOException {

        // Carrega a chave privada do destinatário a partir de um keystore PKCS12 (.pfx).
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream(privateKeystorePath), keystorePassword.toCharArray());
        String alias = ks.aliases().nextElement(); // Assume que há apenas uma chave no keystore.
        PrivateKey privateKey = (PrivateKey) ks.getKey(alias, keystorePassword.toCharArray());

        SecretKey sessionKey;
        try (
                FileInputStream fis = new FileInputStream(inputFilePath);
                DataInputStream dis = new DataInputStream(fis)
        ) {
            // Lê o ficheiro de acordo com a estrutura definida no 'cipherHybrid'.
            int wrappedKeyLength = dis.readInt();
            byte[] wrappedSessionKey = dis.readNBytes(wrappedKeyLength);

            // Usa a chave privada para decifrar (desembrulhar) a chave de sessão AES.
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.UNWRAP_MODE, privateKey);
            sessionKey = (SecretKey) rsaCipher.unwrap(wrappedSessionKey, "AES", Cipher.SECRET_KEY);

            // Lê o resto das partes do ficheiro.
            byte[] iv = dis.readNBytes(IV_SIZE);
            byte[] remainingBytes = dis.readAllBytes();

            // Separa os dados cifrados da tag MAC (que está no final).
            int macSize = Mac.getInstance(MAC_ALG).getMacLength();
            byte[] encryptedData = Arrays.copyOfRange(remainingBytes, 0, remainingBytes.length - macSize);
            byte[] macTagReceived = Arrays.copyOfRange(remainingBytes, remainingBytes.length - macSize, remainingBytes.length);

            // Verifica a autenticidade antes de decifrar.
            Mac mac = Mac.getInstance(MAC_ALG);
            mac.init(sessionKey);
            mac.update(iv);
            mac.update(encryptedData);
            byte[] macTagCalculated = mac.doFinal();

            if (!MessageDigest.isEqual(macTagReceived, macTagCalculated)) {
                return false; // Autenticação falhou!
            }

            // Autenticação bem-sucedida, decifra os dados.
            Cipher aesCipher = Cipher.getInstance(CIPHER_ALG);
            aesCipher.init(Cipher.DECRYPT_MODE, sessionKey, new IvParameterSpec(iv));
            byte[] decryptedData = aesCipher.doFinal(encryptedData);

            try (FileOutputStream fos = new FileOutputStream(outputFilePath)) {
                fos.write(decryptedData);
            }
        }

        return true;
    }


    // MAIN E AJUDA
    private static void usage() {
        System.err.println("Uso (5.1 - Chave Partilhada):");
        System.err.println("  -genkey <ficheiro_chave>");
        System.err.println("  -cipher <ficheiro_in> <ficheiro_chave>");
        System.err.println("  -decipher <ficheiro_in.enc> <ficheiro_chave>");
        System.err.println("\nUso (5.2 - Híbrido/Envelope Digital):");
        System.err.println("  -cipher-h <ficheiro_in> <cert_destinatario.cer> <ficheiro_out.enc>");
        System.err.println("  -decipher-h <ficheiro_in.enc> <keystore_privado.pfx> <password> <ficheiro_out>");
    }

    public static void main(String[] args) {
        if (args.length < 2) {
            usage();
            return;
        }

        try {
            switch (args[0]) {
                // --- Comandos 5.1 ---
                case "-genkey":
                    if (args.length != 2) { usage(); return; }
                    generateKey(args[1]);
                    break;
                case "-cipher":
                    if (args.length != 3) { usage(); return; }
                    cipher(args[1], args[1] + ".enc", args[2]);
                    break;
                case "-decipher":
                    if (args.length != 3) { usage(); return; }
                    String outputDecipherPath = args[1].replace(".enc", "");
                    boolean okDecipher = decipher(args[1], outputDecipherPath, args[2]);
                    System.out.println("Ficheiro decifrado para: " + outputDecipherPath);
                    System.out.println("Verificação de autenticidade: " + (okDecipher ? "SUCESSO" : "FALHOU"));
                    break;

                // --- Comandos 5.2 ---
                case "-cipher-h": // Cifrar para um destinatário com o seu certificado.
                    if (args.length != 4) { usage(); return; }
                    cipherHybrid(args[1], args[3], args[2]);
                    break;
                case "-decipher-h": // Decifrar com o nosso keystore privado.
                    if (args.length != 5) { usage(); return; }
                    boolean okHybrid = decipherHybrid(args[1], args[4], args[2], args[3]);
                    System.out.println("Ficheiro decifrado para: " + args[4]);
                    System.out.println("Verificação de autenticidade: " + (okHybrid ? "SUCESSO" : "FALHOU"));
                    break;

                default:
                    usage();
            }
        } catch (Exception e) {
            System.err.println("Erro: " + e.getMessage());
            e.printStackTrace();
        }
    }
}

/**
 * Classe auxiliar que atualiza um MAC com todos os bytes que passam por ela,
 * antes de os passar para o stream seguinte. Essencial para streaming eficiente.
 */
class MacUpdatingOutputStream extends FilterOutputStream {
    private final Mac mac;

    public MacUpdatingOutputStream(OutputStream out, Mac mac) {
        super(out);
        this.mac = mac;
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        mac.update(b, off, len);
        out.write(b, off, len);
    }

    @Override
    public void write(int b) throws IOException {
        mac.update((byte) b);
        out.write(b);
    }
}