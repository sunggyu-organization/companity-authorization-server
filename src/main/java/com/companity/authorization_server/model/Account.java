package com.companity.authorization_server.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.*;
import lombok.Data;
import lombok.Getter;

import java.util.List;

@Entity(name = "account")
public class Account extends ModelBase{
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String userId;
    private String userName;
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private String userPwd;
    private String userEmail;
    private Boolean isUserPwdExpired;
    private Boolean isUserExpired;

    @Enumerated(EnumType.STRING)
    private Role role;

    public String getUserId() {
        return userId;
    }

    public String getUserName() {
        return userName;
    }

    public String getUserPwd() {
        return userPwd;
    }

    public String getUserEmail() {
        return userEmail;
    }

    public Boolean getUserPwdExpired() {
        return isUserPwdExpired;
    }

    public Boolean getUserExpired() {
        return isUserExpired;
    }

    public Long getId() {
        return id;
    }

    public Role getRole() {
        return role;
    }
}
