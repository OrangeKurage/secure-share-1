package com.secureshare.repository;

import com.secureshare.model.FileEntity;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface FileRepository extends JpaRepository<FileEntity, Long> {
    List<FileEntity> findByOwner_UserId(Long ownerId);

    /** Loads the owner eagerly so callers outside a transaction can read owner fields safely. */
    @Query("select f from FileEntity f join fetch f.owner where f.fileId = :id")
    Optional<FileEntity> findWithOwner(@Param("id") Long id);
}
