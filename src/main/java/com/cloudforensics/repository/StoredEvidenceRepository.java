package com.cloudforensics.repository;

import com.cloudforensics.model.StoredEvidence;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface StoredEvidenceRepository extends MongoRepository<StoredEvidence, String> {
    Optional<StoredEvidence> findByEvidenceId(String evidenceId);
}
