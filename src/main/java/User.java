import com.n1analytics.paillier.EncryptedNumber;
import com.n1analytics.paillier.PaillierPrivateKey;
import com.n1analytics.paillier.cli.SerialisationUtil;
import org.apache.commons.io.IOUtils;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.web.client.RestTemplate;
import tree.Node;
import tree.Tree;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

@SuppressWarnings("ConstantConditions")
public class User {
    private final Tree tree;
    PaillierPrivateKey priv;
    List<String> words;
    HashMap<String, Integer> dictionary = new HashMap<>();
    HashMap<String, Double> idf = new HashMap<>();
    int noFile = 0;
    int alpha = FilePolicyGenerator.alpha;
    BigInteger M = FilePolicyGenerator.M;
    BigInteger maxValue;


    public User(Tree tree, String docPath, String dictionaryFile, PaillierPrivateKey priv) throws IOException {
        this.tree = tree;
        Path dir = Paths.get(docPath);

        /*String privateKeyString = IOUtils.resourceToString("privateKey.priv", Charset.defaultCharset(), Main.class.getClassLoader());
        System.out.println(privateKeyString);

        final ObjectMapper mapper = new ObjectMapper();
        final Map privateKey = mapper.readValue(privateKeyString, Map.class);
        this.priv = SerialisationUtil.unserialise_private(privateKey);*/
        this.priv = priv;

        words = Arrays.asList(IOUtils.resourceToString(dictionaryFile, Charset.defaultCharset(), Main.class.getClassLoader()).split("\\s+"));
        for (int i = 0; i < words.size(); i++) {
            dictionary.put(words.get(i), i);
            idf.put(words.get(i), 0.0);
        }

/*
        DirectoryStream<Path> stream = Files.newDirectoryStream(dir, "*.txt");
        for (Path entry : stream) {
            Set<String> uniqueWord = new HashSet<>();
            Files.lines(Path.of(docPath + entry.getFileName()), StandardCharsets.ISO_8859_1).forEach(line -> {
                line = line.toLowerCase();
                Collections.addAll(uniqueWord, line.split("[\\p{Punct}\\s]+"));
            });

            *//*for (int i = 0; i < uniqueWord.size(); i++) {
                System.out.println(uniqueWord.get(i));
            }*//*

            System.out.println("next file " + entry);

            for (String e : uniqueWord)
                if (idf.containsKey(e)) {
                    idf.put(e, idf.get(e) + 1);
                }
            noFile++;
        }

        for (String e : idf.keySet()) {
            idf.put(e, Math.log10(noFile / idf.get(e)) / Math.log10(2));
        }*/

    }

    public String searchFileSingle(String searchQuery) throws IOException {

        if (!dictionary.containsKey(searchQuery))
            return "Word is not in dictionary";

        int index = dictionary.get(searchQuery);
        Node root = tree.root;
        while (true) {
            EncryptedNumber[] currentValue = tree.currentNode(root);
            if (currentValue == null) {
                break;
            }
         //   networkLoad(currentValue);
            BigInteger decryptedValue = priv.decrypt(currentValue[index]).decodeBigInteger();
            if (decryptedValue.signum() >= 0)
                root = root.left;
            else
                root = root.right;
        }
        return root.id;
    }


    //TODO: This is current rank code
    public String searchFileRanked(String searchQuery, int k) throws IOException {

        if (!dictionary.containsKey(searchQuery))
            return "Word is not in dictionary";

        int index = dictionary.get(searchQuery);
        Node root = tree.root;
        BigInteger decryptedValueRoot = priv.decrypt(tree.root.data[index]).decodeBigInteger();
        var stack = new LinkedList<Integer>();
        while (!decryptedValueRoot.equals(BigInteger.ZERO)) {
            stack.push(decryptedValueRoot.mod(M).intValue());
            decryptedValueRoot = decryptedValueRoot.divide(M);
        }

        int sum = 0;
        while (sum <= k) {
            sum = sum + stack.pop();
        }

//        maxValue = Math.pow(M.intValue(), stack.size());
        maxValue = M.pow(stack.size());
        searchFileRanked(tree.root, index, k);
        while(!q.isEmpty()) {
            System.out.println(q.poll());
        }
        return null;
    }

    PriorityQueue<Map.Entry<String, BigInteger>> q = new PriorityQueue<>((a, b) -> b.getValue().compareTo(a.getValue()));

    public void searchFileRanked(Node root, int index, int k) {

        if(root.left==null && root.right==null){
            if(q.size()<=k-1)
                q.add(Map.entry(root.id, priv.decrypt(root.data[index]).decodeBigInteger()));
            else if(priv.decrypt(root.data[index]).decodeBigInteger().compareTo(q.peek().getValue())>0){
                q.poll();
                q.add(Map.entry(root.id, priv.decrypt(root.data[index]).decodeBigInteger()));
            }
            return;
        }

        EncryptedNumber[] subtractedValue=tree.subtract(root.left.data, root.right.data);
        BigInteger decryptedRoot = priv.decrypt(root.data[index]).decodeBigInteger();
        BigInteger decryptedSubtractedValue = priv.decrypt(subtractedValue[index]).decodeBigInteger();
        BigInteger left = (decryptedRoot.add(decryptedSubtractedValue)).divide(BigInteger.TWO);
        BigInteger right = (decryptedRoot.subtract(decryptedSubtractedValue)).divide(BigInteger.TWO);

        if(left.compareTo(maxValue) >=0 )
            searchFileRanked(root.left, index, k);
        if(right.compareTo(maxValue) >= 0)
            searchFileRanked(root.right, index, k);
    }


    RestTemplate restTemplate = new RestTemplateBuilder()
            .basicAuthentication("mouri", "cloud_thesis")
            .build();
    void networkLoad(EncryptedNumber[] node) throws IOException {

        ByteArrayOutputStream data = new ByteArrayOutputStream();

        for (EncryptedNumber encryptedNumber : node) {
            data.write(SerialisationUtil.serialise_encrypted(encryptedNumber).toString().getBytes());
        }
        String response = restTemplate.postForObject("http://ip-172-31-25-11.ap-southeast-1.compute.internal:8080/echo", data.toByteArray(), String.class);
        System.out.println("Request size is " + response);
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



    public PriorityQueue<Map.Entry<Double, String>> searchRankedK(String searchQuery, int k) {
        String[] splitStr = searchQuery.toLowerCase().split("\\s+");
        List<Integer> indexes = new ArrayList<>();
        for (String word : splitStr) {
            int i = dictionary.getOrDefault(word, -1);
            if (i == -1) continue;
            indexes.add(i);
        }
        PriorityQueue<Map.Entry<Double, String>> docs =  new PriorityQueue<>(Comparator.comparingDouble(Map.Entry::getKey));;
        searchRankedK(tree.root, indexes, k, docs);
        return docs;
    }

    private void searchRankedK(Node root, List<Integer> indexes, int k, PriorityQueue<Map.Entry<Double, String>> docs) {
        if( root.left == null && root.right == null ) {
            double sum = getSum(root, indexes);
            if(docs.size() < k || docs.peek().getKey() < sum) {
                docs.add(Map.entry(sum, root.id));
                if(docs.size() > k) docs.poll();
            }
        }
        else {
            if( docs.size() < k || docs.peek().getKey() < getSum(root, indexes) ) {
                if(root.left != null && root.left.data != null) searchRankedK(root.left, indexes, k, docs);
                if(root.right != null && root.right.data != null) searchRankedK(root.right, indexes, k, docs);
            }
        }
    }

    private double getSum(Node root, List<Integer> indexes) {
        return indexes
                    .stream()
                    .mapToDouble(i -> {
                        BigInteger decrypted = priv.decrypt(root.data[i]).decodeBigInteger();
                        return decodeToTF(decrypted) * idf.get(words.get(i));
                    })
                    .sum();
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
