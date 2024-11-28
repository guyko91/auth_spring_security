package com.pineone.auth.security;

import com.pineone.auth.api.model.User;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

@Getter
public class UserPrincipal implements OAuth2User, UserDetails {

    private final Long id;
    private final String email;
    private final String password;
    @Setter private Map<String, Object> attributes;
    // TODO Spring Security 에서 제공하는 ROLE 을 사용하면 주석 해제.
//    private final Collection<? extends GrantedAuthority> authorities;

    private UserPrincipal(Long id, String email, String password) {
        this.id = id;
        this.email = email;
        this.password = password;
    }

    public static UserPrincipal create(User user) {
        // TODO Spring Security 에서 제공하는 ROLE 을 사용하면 주석 해제.
//        List<GrantedAuthority> authorities = Collections.
//            singletonList(new SimpleGrantedAuthority("ROLE_USER"));
        return new UserPrincipal(
            user.getId(),
            user.getEmail(),
            user.getPassword()
        );
    }

    public static UserPrincipal create(User user, Map<String, Object> attributes) {
        UserPrincipal userPrincipal = UserPrincipal.create(user);
        userPrincipal.setAttributes(attributes);
        return userPrincipal;
    }

    @Override
    public String getUsername() { return email; }

    @Override
    public String getName() { return String.valueOf(id); }

    @Override
    public boolean isAccountNonExpired() { return true; }

    @Override
    public boolean isAccountNonLocked() { return true; }

    @Override
    public boolean isCredentialsNonExpired() { return true; }

    @Override
    public boolean isEnabled() { return true; }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() { return List.of(); }

}
