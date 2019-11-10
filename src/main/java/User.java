import com.fasterxml.jackson.databind.ObjectMapper;
import com.n1analytics.paillier.EncryptedNumber;
import com.n1analytics.paillier.PaillierPrivateKey;
import com.n1analytics.paillier.cli.SerialisationUtil;
import org.apache.commons.io.IOUtils;
import tree.Node;
import tree.Tree;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

public class User {
    private final Tree tree;
    PaillierPrivateKey priv;
    List<String> words;
    HashMap<String, Integer> dictionary = new HashMap<>();
    HashMap<String, Double> idf = new HashMap<>();
    int noFile = 0;
    int alpha = FilePolicyGenerator.alpha;
    BigInteger M = FilePolicyGenerator.M;


    public User(Tree tree, String docPath) throws IOException {
        this.tree = tree;
        Path dir = Paths.get(docPath);

        String privateKeyString = IOUtils.resourceToString("privateKey.priv", Charset.defaultCharset(), Main.class.getClassLoader());
        System.out.println(privateKeyString);

        final ObjectMapper mapper = new ObjectMapper();
        final Map privateKey = mapper.readValue(privateKeyString, Map.class);
        priv = SerialisationUtil.unserialise_private(privateKey);

        words = Arrays.asList(IOUtils.resourceToString("dictionary.txt", Charset.defaultCharset(), Main.class.getClassLoader()).split("\\s+"));
        for (int i = 0; i < words.size(); i++) {
            dictionary.put(words.get(i), i);
            idf.put(words.get(i), 0.0);
        }


        DirectoryStream<Path> stream = Files.newDirectoryStream(dir, "*.txt");
        for (Path entry : stream) {
            Set<String> uniqueWord = new HashSet<>();
            Files.lines(Path.of(docPath + entry.getFileName()), StandardCharsets.ISO_8859_1).forEach(line -> {
                line = line.toLowerCase();
                Collections.addAll(uniqueWord, line.split("[\\p{Punct}\\s]+"));
            });

            /*for (int i = 0; i < uniqueWord.size(); i++) {
                System.out.println(uniqueWord.get(i));
            }*/

            System.out.println("next file " + entry);

            for (String e : uniqueWord)
                if (idf.containsKey(e)) {
                    idf.put(e, idf.get(e) + 1);
                }
            noFile++;
        }

        for (String e : idf.keySet()) {
            idf.put(e, Math.log10(noFile / idf.get(e)) / Math.log10(2));
        }

    }

    public String searchFile(String searchQuery) {

        String[] splitStr = searchQuery.split("\\s+");

//        for(String e: splitStr ){
//           if (!dictionary.containsKey(searchQuery))
//            return "Word is not in dictionary";
//        }

        Node root = tree.root;
        EncryptedNumber[] rootData = tree.root.data;

        while (true) {
            EncryptedNumber[] subtractedValue = tree.currentNode(root);
            if (subtractedValue == null)
                break;

            BigInteger[] decryptedRoot = new BigInteger[dictionary.size()];
            BigInteger[] decryptedSubtractedValue = new BigInteger[dictionary.size()];

            double sumOfLeft = 0, sumOfRight = 0, tfOfLeft, tfOfRight;
            BigInteger left, right;
            int i;

            for (String word : splitStr) {

                i = dictionary.getOrDefault(word, -1);
                if (i == -1) continue;
                decryptedRoot[i] = priv.decrypt(rootData[i]).decodeBigInteger();
                decryptedSubtractedValue[i] = priv.decrypt(subtractedValue[i]).decodeBigInteger();
                left = (decryptedRoot[i].add(decryptedSubtractedValue[i])).divide(BigInteger.TWO);
                tfOfLeft = decodeToTF(left);
                sumOfLeft = sumOfLeft + tfOfLeft * idf.get(word);

                right = (decryptedRoot[i].subtract(decryptedSubtractedValue[i])).divide(BigInteger.TWO);
                tfOfRight = decodeToTF(right);
                sumOfRight = sumOfRight + tfOfRight * idf.get(word);

            }

            if (sumOfLeft + 1e-7 >= sumOfRight) {
                root = root.left;
                rootData = root.data;
            } else {
                root = root.right;
                rootData = root.data;
            }
        }


        return root.id;
    }

    private double decodeToTF(BigInteger b) {
        int cnt = 0;
        while (b.compareTo(M) >= 0) {
            cnt++;
            b = b.divide(M);
        }
        return ((double) cnt) / alpha;
    }
}
