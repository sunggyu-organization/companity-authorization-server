package com.companity.authorization_server.adapter.jpa;

import java.util.Optional;

import com.companity.authorization_server.adapter.jpa.entity.Client;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ClientRepository extends JpaRepository<Client, String> {
    Optional<Client> findByClientId(String clientId);
}