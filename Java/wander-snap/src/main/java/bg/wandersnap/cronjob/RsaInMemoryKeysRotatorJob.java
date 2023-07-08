package bg.wandersnap.cronjob;

import bg.wandersnap.security.RsaInMemoryKeyProvider;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

@Component
public class RsaInMemoryKeysRotatorJob {
    private static final int TIME_TO_ROTATE_ACCESS_TOKEN_KEYS = 1_800_000;
    private final RsaInMemoryKeyProvider rsaInMemoryKeyProvider;

    public RsaInMemoryKeysRotatorJob(final RsaInMemoryKeyProvider rsaInMemoryKeyProvider) {
        this.rsaInMemoryKeyProvider = rsaInMemoryKeyProvider;
    }

    @Scheduled(fixedRate = TIME_TO_ROTATE_ACCESS_TOKEN_KEYS)
    public void rotateAccessTokenInMemoryRsaKeys() throws NoSuchAlgorithmException, InvalidKeySpecException {
        this.rsaInMemoryKeyProvider.rotateInMemoryKeys();
    }
}