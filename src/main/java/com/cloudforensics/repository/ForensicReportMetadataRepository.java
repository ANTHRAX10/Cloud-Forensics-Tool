package com.cloudforensics.repository;

import com.cloudforensics.model.ForensicReportMetadata;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * Spring Data JPA repository for persisting and querying forensic report metadata.
 * The backing store is the H2 in-memory database; all data is lost on restart.
 */
@Repository
public interface ForensicReportMetadataRepository
        extends JpaRepository<ForensicReportMetadata, String> {

    /**
     * Returns all report metadata entries ordered by generation time (newest first).
     * Used by GET /api/reports.
     */
    List<ForensicReportMetadata> findAllByOrderByGeneratedAtDesc();
}
