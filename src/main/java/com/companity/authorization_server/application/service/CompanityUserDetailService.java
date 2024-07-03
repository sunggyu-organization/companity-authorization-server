package com.companity.authorization_server.application.service;

import com.companity.authorization_server.model.Account;
import com.companity.authorization_server.model.Role;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.List;

public class CompanityUserDetailService implements UserDetailsService {

    @Autowired
    private AccountService accountService;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Account user = accountService.getByUserName(username);

        if (user == null) {
            throw new UsernameNotFoundException(username);
        }

        return new User(user.getUserId(), user.getUserPwd(), true, !user.getUserExpired(), !user.getUserPwdExpired(), true, AuthorityUtils.createAuthorityList(user.getRole().name()));
    }
}
