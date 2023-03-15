package com.visionrent.security.service;

import com.visionrent.domain.User;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;
/**
 * 1. CLASS TO IMPLEMENT
 * Security helper class-2
 * this class is uses our user which has been fetched from DB by UserDetailsServiceImpl class loadUserByUsername method.
 * the user will be fulfilled with user details.
 * User details are overwritten methods below.
 * At the end we have UserDetailsImpl object that has credentials and user details.
 */
@Getter
@Setter
@AllArgsConstructor
public class UserDetailsImpl implements UserDetails {

    private String email;

    private String password;

    private Collection<? extends GrantedAuthority> authorities;


    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }



    public static UserDetailsImpl build(User user){
        List<SimpleGrantedAuthority> authorities =
                user.getRoles().stream()
                        .map(role -> new SimpleGrantedAuthority(role.getType().name())).collect(Collectors.toList());
        return new UserDetailsImpl(user.getEmail(), user.getPassword(), authorities);
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public String getUsername() {
        return this.email;
    }

    // methods that return TRUE can be changed according to business needs;
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
