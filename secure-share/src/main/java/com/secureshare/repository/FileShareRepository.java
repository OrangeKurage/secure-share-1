package com.secureshare.repository;

import com.secureshare.model.FileShare;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface FileShareRepository extends JpaRepository<FileShare, Long> {
    List<FileShare> findByRecipient_UserId(Long recipientId);
    Optional<FileShare> findByFile_FileIdAndRecipient_UserId(Long fileId, Long recipientId);
    List<FileShare> findByFile_FileId(Long fileId);

    /** Everything the owner needs to see who has access (recipient fetched eagerly). */
    @Query("select s from FileShare s join fetch s.recipient where s.file.fileId = :fileId order by s.shareDate desc")
    List<FileShare> findAllForFile(@Param("fileId") Long fileId);

    /** "Shared with me": active and not expired, with file + owner fetched eagerly. */
    @Query("select s from FileShare s join fetch s.file f join fetch f.owner "
         + "where s.recipient.userId = :userId "
         + "and s.status = com.secureshare.model.ShareStatus.ACTIVE "
         + "and (s.expiryDate is null or s.expiryDate > :now) "
         + "order by s.shareDate desc")
    List<FileShare> findActiveForRecipient(@Param("userId") Long userId, @Param("now") Instant now);
}
