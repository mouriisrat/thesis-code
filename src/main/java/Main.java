import com.fasterxml.jackson.databind.ObjectMapper;
import com.n1analytics.paillier.EncryptedNumber;
import com.n1analytics.paillier.PaillierContext;
import com.n1analytics.paillier.PaillierPrivateKey;
import com.n1analytics.paillier.PaillierPublicKey;
import com.n1analytics.paillier.cli.SerialisationUtil;
import org.apache.commons.io.IOUtils;
import org.springframework.util.StopWatch;
import tree.Tree;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.Charset;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) throws IOException {
        System.setErr(new PrintStream(OutputStream.nullOutputStream()));

        String publicKeyString = IOUtils.resourceToString("publicKey.pub", Charset.defaultCharset(), Main.class.getClassLoader());
        System.out.println(publicKeyString);
        String privateKeyString = IOUtils.resourceToString("privateKey.priv", Charset.defaultCharset(), Main.class.getClassLoader());
        System.out.println(privateKeyString);

        final ObjectMapper mapper = new ObjectMapper();
        final Map publicKey = mapper.readValue(publicKeyString, Map.class);
        final Map privateKey = mapper.readValue(privateKeyString, Map.class);

        PaillierPublicKey pub = SerialisationUtil.unserialise_public(publicKey);
        PaillierPrivateKey priv = SerialisationUtil.unserialise_private(privateKey);
        PaillierContext signedContext = pub.createSignedContext();
        FilePolicyGenerator filePolicyGenerator = new FilePolicyGenerator();
        StopWatch stopWatch = new StopWatch();
        Tree tree = new Tree();
        Scanner user_input = new Scanner(System.in);
        User user = new User(tree);

       /* stopWatch.start();
        EncryptedNumber[] filePolicyEncrypted = filePolicyGenerator.filePolicyEncrypt("E:\\Thesis Data\\testt\\rfc8628.txt", signedContext);
        stopWatch.stop();

        System.out.println(SerialisationUtil.serialise_encrypted(filePolicyEncrypted[0]));
        System.out.println("Time to encrypt a file " + stopWatch.getLastTaskInfo().getTimeMillis());

*/

        Path dir;
        dir = Paths.get("E:\\Thesis Data\\test\\");
        EncryptedNumber[] data;
        String id, searchQuery;

        try (DirectoryStream<Path> stream = Files.newDirectoryStream(dir, "*.txt")) {
            for (Path entry : stream) {
                stopWatch.start();
                data = filePolicyGenerator.filePolicyEncrypt("E:\\Thesis Data\\test\\" + entry.getFileName(), signedContext);
                id = entry.getFileName().toString();
                tree.insert(data, id);
                stopWatch.stop();
                System.out.print("Root :");
                for (int i = 0; i < tree.root.data.length; i++) {
                    System.out.print(" " + priv.decrypt(tree.root.data[i]).decodeBigInteger());
                }
                System.out.println("\nTime to encrypt a file " + stopWatch.getLastTaskInfo().getTimeMillis());
                // System.out.println(entry.getFileName());
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println("Enter a keyword");
        while (user_input.hasNext()) {
            searchQuery = user_input.next();
            if (searchQuery.equals("quit")) {
                break;
            }
            System.out.println("The file name is = " + user.searchFile(searchQuery));
            System.out.println("Enter a keyword");
        }
    }
}

