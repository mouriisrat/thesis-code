import com.fasterxml.jackson.databind.ObjectMapper;
import com.n1analytics.paillier.PaillierContext;
import com.n1analytics.paillier.PaillierPublicKey;
import com.n1analytics.paillier.cli.SerialisationUtil;
import org.apache.commons.io.IOUtils;
import org.springframework.util.StopWatch;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;

public class Main {

    public static void main(String[] args) throws IOException {


        String publicKeyString = IOUtils.resourceToString("publicKey.pub", Charset.defaultCharset(), Main.class.getClassLoader());
        System.out.println(publicKeyString);

        final ObjectMapper mapper = new ObjectMapper();
        final Map publicKey = mapper.readValue(publicKeyString, Map.class);

        PaillierPublicKey pub = SerialisationUtil.unserialise_public(publicKey);
        PaillierContext signedContext = pub.createSignedContext();
        FilePolicyGenerator filePolicyGenerator = new FilePolicyGenerator();
        StopWatch stopWatch = new StopWatch();

       /* stopWatch.start();
        EncryptedNumber[] filePolicyEncrypted = filePolicyGenerator.filePolicyEncrypt("E:\\Thesis Data\\testt\\rfc8628.txt", signedContext);
        stopWatch.stop();

        System.out.println(SerialisationUtil.serialise_encrypted(filePolicyEncrypted[0]));
        System.out.println("Time to encrypt a file " + stopWatch.getLastTaskInfo().getTimeMillis());

*/

        Path dir;
        dir = Paths.get("E:\\Thesis Data\\test\\");

        try (DirectoryStream<Path> stream = Files.newDirectoryStream(dir, "*.txt")) {
            for (Path entry : stream) {
                stopWatch.start();
                filePolicyGenerator.filePolicyEncrypt("E:\\Thesis Data\\test\\" + entry.getFileName(), signedContext);
                stopWatch.stop();

                System.out.println("Time to encrypt a file " + stopWatch.getLastTaskInfo().getTimeMillis());
                // System.out.println(entry.getFileName());
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

