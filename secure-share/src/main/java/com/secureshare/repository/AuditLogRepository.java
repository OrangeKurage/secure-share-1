package com.secureshare.repository;

import com.secureshare.model.AuditLog;
import java.util.List;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {
    List<AuditLog> findByUser_UserIdOrderByTimestampDesc(Long userId);
    List<AuditLog> findByFile_FileIdOrderByTimestampDesc(Long fileId);

    /** One user's own events, newest first. User and file are fetched so callers need no open session. */
    @Query("select a from AuditLog a left join fetch a.user u left join fetch a.file f "
         + "where u.userId = :userId order by a.timestamp desc, a.logId desc")
    List<AuditLog> findForUser(@Param("userId") Long userId, Pageable pageable);

    /** Everyone's events on one file, newest first. */
    @Query("select a from AuditLog a left join fetch a.user u left join fetch a.file f "
         + "where f.fileId = :fileId order by a.timestamp desc, a.logId desc")
    List<AuditLog> findForFile(@Param("fileId") Long fileId, Pageable pageable);
}
