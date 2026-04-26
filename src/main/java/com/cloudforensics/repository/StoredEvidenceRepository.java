package com.cloudforensics.repository;

import com.cloudforensics.model.StoredEvidence;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface StoredEvidenceRepository extends JpaRepository<StoredEvidence, Long> {
    Optional<StoredEvidence> findByEvidenceId(String evidenceId);
}
