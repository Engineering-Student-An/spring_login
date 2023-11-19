package practice.login.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import practice.login.domain.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    boolean existsByLoginId(String loginId);

    boolean existsByNickname(String nickname);

    Optional<User> findByLoginId(String loginId);
}
