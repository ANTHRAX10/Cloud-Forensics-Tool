package com.cloudforensics.repository;

import com.cloudforensics.model.IncidentCase;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface CaseRepository extends MongoRepository<IncidentCase, String> {
}
