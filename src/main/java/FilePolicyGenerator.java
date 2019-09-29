import com.n1analytics.paillier.EncryptedNumber;
import com.n1analytics.paillier.PaillierContext;
import org.apache.commons.io.IOUtils;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

public class FilePolicyGenerator {
    int alpha = 10;
    BigInteger M = BigInteger.valueOf(10);
    List<String> words;
    HashMap<String, Integer> dictionary = new HashMap<>();

    public FilePolicyGenerator() throws IOException {

        words = Arrays.asList(IOUtils.resourceToString("dictionary.txt", Charset.defaultCharset(), Main.class.getClassLoader()).split("\\s+"));

        for (int i = 0; i < words.size(); i++) {
            dictionary.put(words.get(i), i);
        }
    }

    public EncryptedNumber[] filePolicyEncrypt(String fileName, PaillierContext context) throws IOException {

        int[] frequency = new int[dictionary.size()];
        var ref = new Object() {
            int maxFrequency = 1;
        };
        Files.lines(Path.of(fileName)).forEach(line -> {
            line=line.toLowerCase();
            for (String word : line.split("[\\p{Punct}\\s]+")) {
                if (dictionary.containsKey(word)) {
                    frequency[dictionary.get(word)]++;
                    ref.maxFrequency = Math.max(frequency[dictionary.get(word)], ref.maxFrequency);
                }
            }
        });

        EncryptedNumber[] cipherText = new EncryptedNumber[dictionary.size()];
        System.out.print(" plaintext" );
        for (int i = 0; i < dictionary.size(); i++) {
            long temp = Math.round(((double) alpha * frequency[i]) / ref.maxFrequency);
            BigInteger plainText = M.pow((int) temp);
            System.out.print(" "+plainText);
            cipherText[i] = context.encrypt(plainText);
        }
        System.out.println();
        return cipherText;
    }
}
