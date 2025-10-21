package ex5;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class ex5 {

    private static final String CIPHER_ALG = "AES/CBC/PKCS5Padding";
    private static final String MAC_ALG = "HmacSHA256";
    private static final int IV_SIZE = 16;


    /**
     * Gera uma chave simétrica aleatória e guarda-a num ficheiro.
     */
    public static void generateKey(String keyFilePath) throws NoSuchAlgorithmException, IOException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128); // Chave de 128 bits
        SecretKey secretKey = keyGen.generateKey();
        Files.write(Path.of(keyFilePath), secretKey.getEncoded());
        System.out.println("Chave aleatória gerada e guardada em: " + keyFilePath);
    }

    /**
     * Cifra um ficheiro usando o esquema Encrypt-then-MAC de forma eficiente.
     */
    public static void cipher(String inputFilePath, String outputFilePath, String keyFilePath)
            throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException {

        // 1. Ler a chave e inicializar Cipher e Mac
        byte[] keyBytes = Files.readAllBytes(Path.of(keyFilePath));
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");

        Cipher cipher = Cipher.getInstance(CIPHER_ALG);
        // O IV será gerado pelo próprio Cipher, que é uma prática mais segura e simples
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] iv = cipher.getIV();

        Mac mac = Mac.getInstance(MAC_ALG);
        mac.init(secretKey);

        // 2. Abrir os streams
        try (InputStream in = new FileInputStream(inputFilePath);
             FileOutputStream fos = new FileOutputStream(outputFilePath)) {

            // 3. Escrever o IV não codificado no início do ficheiro de saída
            fos.write(iv);

            // 4. Criar um stream que calcula o MAC à medida que os dados cifrados são escritos
            try (MacUpdatingOutputStream macOut = new MacUpdatingOutputStream(fos, mac);
                 CipherOutputStream cos = new CipherOutputStream(macOut, cipher)) {

                // 5. Ler o ficheiro original e escrever no CipherOutputStream.
                // Isto faz com que os dados sejam cifrados e passem para o MacUpdatingOutputStream,
                // que por sua vez os escreve no ficheiro e atualiza o MAC.
                in.transferTo(cos);
            }

            // 6. Obter a tag MAC final e anexá-la ao ficheiro
            byte[] macTag = mac.doFinal();
            fos.write(macTag);
        }
        System.out.println("Ficheiro cifrado e autenticado guardado em: " + outputFilePath);
    }

    /**
     * Decifra e verifica um ficheiro.
     */
    public static boolean decipher(String inputFilePath, String outputFilePath, String keyFilePath) {
        // A ser implementado
        System.out.println("Funcionalidade de decifra a ser implementada.");
        return false;
    }


    private static void usage() {
        System.err.println("Uso:");
        System.err.println("  -genkey <ficheiro_chave>");
        System.err.println("  -cipher <ficheiro_a_proteger> <ficheiro_chave>");
        System.err.println("  -decipher <ficheiro_a_desproteger> <ficheiro_chave>");
    }

    public static void main(String[] args) {
        if (args.length < 2) {
            usage();
            return;
        }

        try {
            switch (args[0]) {
                case "-genkey":
                    if (args.length != 2) { usage(); return; }
                    generateKey(args[1]);
                    break;
                case "-cipher":
                    if (args.length != 3) { usage(); return; }
                    String outputCipherPath = args[1] + ".enc";
                    cipher(args[1], outputCipherPath, args[2]);
                    break;
                case "-decipher":
                    if (args.length != 3) { usage(); return; }
                    String outputDecipherPath = args[1].replace(".enc", ".dec");
                    boolean ok = decipher(args[1], outputDecipherPath, args[2]);
                    System.out.println(ok ? "Verificação de autenticidade: SUCESSO" : "Verificação de autenticidade: FALHOU");
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
 * Uma classe auxiliar que funciona como um "wrapper" para um OutputStream.
 * Todos os bytes escritos neste stream são passados para o stream subjacente
 * e também são usados para atualizar uma instância de Mac.
 */
class MacUpdatingOutputStream extends FilterOutputStream {
    private final Mac mac;

    public MacUpdatingOutputStream(OutputStream out, Mac mac) {
        super(out);
        this.mac = mac;
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        out.write(b, off, len);
        mac.update(b, off, len);
    }

    @Override
    public void write(int b) throws IOException {
        out.write(b);
        mac.update((byte) b);
    }
}