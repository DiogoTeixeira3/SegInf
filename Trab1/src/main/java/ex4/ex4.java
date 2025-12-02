package ex4;

import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.*;




public class ex4 {
    public static void main(String[] args) throws Exception {

        // === 1. Ler os ficheiros GoodApp.java e BadApp.java ===
        // Lê todo o conteúdo de cada ficheiro como um vetor de bytes.
        byte[] good = Files.readAllBytes(Path.of("GoodApp.java"));
        byte[] bad = Files.readAllBytes(Path.of("BadApp.java"));

        // === 2. Criar o objeto de hash SHA-256 ===
        // O MessageDigest fornece a implementação da função de hash indicada.
        MessageDigest md = MessageDigest.getInstance("SHA-256");

        // Calcula o hash completo de GoodApp.java
        byte[] goodHash = md.digest(good);

        // Extrai os primeiros 16 bits (dois primeiros bytes) do hash SHA-256
        int target0 = goodHash[0] & 0xff;
        int target1 = goodHash[1] & 0xff;

        // Mostra no ecrã o valor H16 de referência (em hexadecimal)
        System.out.printf("Target H16: %02x%02x%n", target0, target1);

        // Marca o tempo de início para medir o tempo de execução do ataque
        long start = System.nanoTime();

        // === 3. Inicia a procura (ataque de colisão parcial) ===
        // Tenta gerar versões ligeiramente diferentes do BadApp.java
        // acrescentando linhas de comentário com um "nonce" diferente.
        for (int i = 0; i < 1_000_000; i++) {

            // Cria uma nova versão candidata do código-fonte:
            // adiciona um comentário diferente em cada iteração.
            String candidate = new String(bad, StandardCharsets.UTF_8)
                    + "\n// nonce " + i;

            // Calcula o hash SHA-256 da versão candidata
            byte[] h = md.digest(candidate.getBytes(StandardCharsets.UTF_8));

            // Verifica se os dois primeiros bytes (16 bits) coincidem com os de GoodApp.java
            if ((h[0] & 0xff) == target0 && (h[1] & 0xff) == target1) {

                // Se encontrar coincidência, calcula o tempo total de execução
                long end = System.nanoTime();
                double seconds = (end - start) / 1_000_000_000.0;

                // Mostra no ecrã o nonce encontrado e o tempo decorrido
                System.out.printf("Found match! nonce=%d | Time: %.3f s%n", i, seconds);

                // Guarda a versão modificada do BadApp que produz o mesmo H16
                Files.writeString(Path.of("BadApp_match.java"), candidate);

                // Termina o ciclo, pois a colisão parcial foi encontrada
                break;
            }
        }
    }
}
