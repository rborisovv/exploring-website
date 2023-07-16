package bg.wandersnap.cronjob;

import bg.wandersnap.dao.RefreshTokenRepository;
import bg.wandersnap.model.RefreshToken;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.Set;

@Component
public class RefreshKeyRemovalJob {
    private final RefreshTokenRepository refreshTokenRepository;

    public RefreshKeyRemovalJob(final RefreshTokenRepository refreshTokenRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
    }

    @Scheduled(cron = "@midnight")
    public void rotateAccessTokenInMemoryRsaKeys() {
        final Set<RefreshToken> expiredRefreshTokens = this.refreshTokenRepository
                .getRefreshTokensByExpirationTimeBefore(LocalDateTime.now());

        this.refreshTokenRepository.deleteAll(expiredRefreshTokens);
    }
}