package com.secureshare.repository;

import com.secureshare.model.Session;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SessionRepository extends JpaRepository<Session, Long> {
    Optional<Session> findByJwtToken(String jwtToken);
}
