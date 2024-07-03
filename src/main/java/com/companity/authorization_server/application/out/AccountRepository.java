package com.companity.authorization_server.application.out;

import com.companity.authorization_server.model.Account;

public interface AccountRepository {
    Account getByUserName(String username);
}
