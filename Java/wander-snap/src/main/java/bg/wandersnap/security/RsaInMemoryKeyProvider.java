package bg.wandersnap.security;

import jakarta.annotation.PostConstruct;
import lombok.Getter;
import org.springframework.stereotype.Component;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

@Component
@Getter
public final class RsaInMemoryKeyProvider {
    private RSAPrivateKey rsaPrivateKey;
    private RSAPublicKey rsaPublicKey;
    private KeyFactory keyFactory;

    @PostConstruct
    private void rosaKeysInitializer() throws NoSuchAlgorithmException, InvalidKeySpecException {
        this.keyFactory = KeyFactory.getInstance("RSA");
        this.rotateInMemoryKeys();
    }

    public void rotateInMemoryKeys() throws NoSuchAlgorithmException, InvalidKeySpecException {
        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);

        final KeyPair keyPair = keyPairGenerator.generateKeyPair();

        final PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded());
        final X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(keyPair.getPublic().getEncoded());

        this.rsaPrivateKey = (RSAPrivateKey) this.keyFactory.generatePrivate(privateSpec);
        this.rsaPublicKey = (RSAPublicKey) this.keyFactory.generatePublic(publicSpec);
    }
}