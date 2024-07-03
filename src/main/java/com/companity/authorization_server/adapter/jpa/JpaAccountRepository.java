package com.companity.authorization_server.adapter.jpa;

import com.companity.authorization_server.model.Account;
import org.springframework.data.jpa.repository.JpaRepository;

public interface JpaAccountRepository extends JpaRepository<Account, String> {
    Account findByUserName(String username);
}
