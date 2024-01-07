package practice.login.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import practice.login.domain.Member;

public interface MemberRepository extends JpaRepository<Member, Long> {

    boolean existsByLoginId(String loginId);

    Member findByLoginId(String loginId);
}
