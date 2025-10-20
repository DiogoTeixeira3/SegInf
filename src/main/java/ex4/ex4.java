package ex4;

import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.*;




public class ex4 {
    public static void main(String[] args) throws Exception {
        byte[] good = Files.readAllBytes(Path.of("GoodApp.java")); // faz a leitura de ambos os ficheiros e guarda o conjunto de bytes
        byte[] bad = Files.readAllBytes(Path.of("BadApp.java"));

        MessageDigest md = MessageDigest.getInstance("SHA-256"); // especifica qual o algoritmo a utilizar na função de hash, neste caso é o SHA-256
        byte[] goodHash = md.digest(good);
        int target0 = goodHash[0] & 0xff, target1 = goodHash[1] & 0xff; // guarda os primeiros 16 bits desse hash

        System.out.printf("Target H16: %02x%02x%n", target0, target1);

        long start = System.nanoTime();

        for (int i = 0; i < 1_000_000; i++) {
            String candidate = new String(bad, StandardCharsets.UTF_8) + "\n// nonce " + i; // vamos adicionado empty lines para conseguirmos obter o mesmo output que badJAva mas funções de hash diferentes
            byte[] h = md.digest(candidate.getBytes(StandardCharsets.UTF_8));
            if ((h[0] & 0xff) == target0 && (h[1] & 0xff) == target1) {
            long end = System.nanoTime(); 
                double seconds = (end - start) / 1_000_000_000.0;
                System.out.printf("Found match! nonce=%d | Time: %.3f s%n", i, seconds);
                Files.writeString(Path.of("BadApp_match.java"), candidate);
                break;
            }
        }

    }
}
