package com.companity.authorization_server.adapter;

import com.companity.authorization_server.adapter.jpa.JpaAccountRepository;
import com.companity.authorization_server.application.out.AccountRepository;
import com.companity.authorization_server.model.Account;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

@Repository
public class AccountRepositoryImpl implements AccountRepository {

    @Autowired
    private JpaAccountRepository jpaAccountRepository;
    @Override
    public Account getByUserName(String username) {
        return jpaAccountRepository.findByUserName(username);
    }
}
