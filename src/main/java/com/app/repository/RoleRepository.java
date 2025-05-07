package com.app.repository;

import org.springframework.stereotype.Repository;

import com.app.models.ERole;
import com.app.models.Role;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

 

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
  Optional<Role> findByName(ERole name);
}
