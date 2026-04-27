package com.cloudforensics.repository;

import com.cloudforensics.model.LogEvent;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface LogRepository extends MongoRepository<LogEvent, String> {
}
