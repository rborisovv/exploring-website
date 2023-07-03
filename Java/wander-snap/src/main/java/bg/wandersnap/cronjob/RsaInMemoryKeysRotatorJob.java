package bg.wandersnap.cronjob;

import bg.wandersnap.security.RsaInMemoryKeyProvider;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

@Component
public class RsaInMemoryKeysRotatorJob {
    private final RsaInMemoryKeyProvider rsaInMemoryKeyProvider;

    public RsaInMemoryKeysRotatorJob(final RsaInMemoryKeyProvider rsaInMemoryKeyProvider) {
        this.rsaInMemoryKeyProvider = rsaInMemoryKeyProvider;
    }

    @Scheduled(fixedRate = 5000, initialDelay = 5000)
    public void rotateAccessTokenInMemoryRsaKeys() throws NoSuchAlgorithmException, InvalidKeySpecException {
        System.out.println("Rotated");
        this.rsaInMemoryKeyProvider.rotateInMemoryKeys();
    }
}