package com.companity.authorization_server.application.service;

import com.companity.authorization_server.application.out.AccountRepository;
import com.companity.authorization_server.model.Account;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class AccountService {

    @Autowired
    private AccountRepository accountRepository;

    public Account getByUserName(String username) {
        return accountRepository.getByUserName(username);
    }
}
