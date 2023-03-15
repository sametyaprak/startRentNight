package com.visionrent.repository;

import com.visionrent.domain.User;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User,Long> {


    @EntityGraph(attributePaths = "roles")
    Optional<User>findByEmail(String email);

}
