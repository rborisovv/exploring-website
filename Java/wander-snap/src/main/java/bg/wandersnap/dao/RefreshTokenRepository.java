package bg.wandersnap.dao;

import bg.wandersnap.model.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.Set;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    @Query("SELECT rt FROM RefreshToken as rt where rt.user.username = :username")
    Optional<RefreshToken> getRefreshTokenByUsername(@Param("username") final String username);

    Set<RefreshToken> getRefreshTokensByExpirationTimeBefore(LocalDateTime expirationTime);
}