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
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class User {
    private final Tree tree;
    PaillierPrivateKey priv;
    List<String> words;
    HashMap<String, Integer> dictionary = new HashMap<>();


    public User(Tree tree) throws IOException {
        this.tree = tree;

        String privateKeyString = IOUtils.resourceToString("privateKey.priv", Charset.defaultCharset(), Main.class.getClassLoader());
        System.out.println(privateKeyString);

        final ObjectMapper mapper = new ObjectMapper();
        final Map privateKey = mapper.readValue(privateKeyString, Map.class);
        priv = SerialisationUtil.unserialise_private(privateKey);

        words = Arrays.asList(IOUtils.resourceToString("dictionary.txt", Charset.defaultCharset(), Main.class.getClassLoader()).split("\\s+"));
        for (int i = 0; i < words.size(); i++) {
            dictionary.put(words.get(i), i);
        }
    }

    public String searchFile(String searchQuery) {

        if (!dictionary.containsKey(searchQuery))
            return "Word is not in dictionary";

        int index = dictionary.get(searchQuery);
        Node root = tree.root;
        while (true) {
            EncryptedNumber[] currentValue = tree.currentNode(root);
            if (currentValue == null)
                break;
            BigInteger decryptedValue = priv.decrypt(currentValue[index]).decodeBigInteger();
            if (decryptedValue.signum() >= 0)
                root = root.left;
            else
                root = root.right;
        }


        return root.id;
    }
}
