package com.companity.authorization_server.model;

public enum Role {
    ADMIN("ADMIN"),
    MANAGER("MANAGER"),
    USER("USER");

    private String code;

    Role(String code) {
        this.code = code;
    }
}
