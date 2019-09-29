import com.n1analytics.paillier.EncryptedNumber;
import com.n1analytics.paillier.PaillierContext;
import com.n1analytics.paillier.PaillierPrivateKey;
import com.n1analytics.paillier.cli.PrivateKeyJsonSerialiser;
import com.n1analytics.paillier.cli.SerialisationUtil;

import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;

public class KeyGenerator {
    public static void main(String[] arg) throws NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException {

        PaillierPrivateKey privateKey = PaillierPrivateKey.create(704);

        PrivateKeyJsonSerialiser serializedPrivateKey = new PrivateKeyJsonSerialiser("");
        privateKey.serialize(serializedPrivateKey);
        System.out.println(serializedPrivateKey);

        /*PublicKeyJsonSerialiser serializedPublicKey = PublicKeyJsonSerialiser.class.getConstructor(String.class).newInstance("");
        serializedPublicKey.serialize(privateKey.getPublicKey());
        System.out.println(serializedPrivateKey);*/


        PaillierContext signedContext = privateKey.getPublicKey().createSignedContext();

        EncryptedNumber a = signedContext.encrypt(BigInteger.valueOf(5));
        System.out.println(SerialisationUtil.serialise_encrypted(a));
        System.out.println(a.decrypt(privateKey).decodeBigInteger());

    }
}
