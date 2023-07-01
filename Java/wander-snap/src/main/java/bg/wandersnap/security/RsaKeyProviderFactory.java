package bg.wandersnap.security;

import com.auth0.jwt.interfaces.RSAKeyProvider;
import lombok.AllArgsConstructor;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@AllArgsConstructor
public final class RsaKeyProviderFactory implements RSAKeyProvider {
    private final RSAPrivateKey rsaPrivateKey;
    private final RSAPublicKey rsaPublicKey;

    @Override
    public RSAPublicKey getPublicKeyById(final String keyId) {
        return this.rsaPublicKey;
    }

    @Override
    public RSAPrivateKey getPrivateKey() {
        return this.rsaPrivateKey;
    }

    @Override
    public String getPrivateKeyId() {
        return null;
    }
}