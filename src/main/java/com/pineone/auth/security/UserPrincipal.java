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

    private final Long seq;
    private final String id;
    private final String name;
    private final String password;
    @Setter private Map<String, Object> attributes;
    // TODO Spring Security 에서 제공하는 ROLE 을 사용하면 주석 해제.
//    private final Collection<? extends GrantedAuthority> authorities;

    private UserPrincipal(Long seq, String id, String name, String password) {
        this.seq = seq;
        this.id = id;
        this.name = name;
        this.password = password;
    }

    public static UserPrincipal create(User user) {
        // TODO Spring Security 에서 제공하는 ROLE 을 사용하면 주석 해제.
//        List<GrantedAuthority> authorities = Collections.
//            singletonList(new SimpleGrantedAuthority("ROLE_USER"));
        return new UserPrincipal(
            user.getSeq(),
            user.getId(),
            user.getName(),
            user.getPassword()
        );
    }

    public static UserPrincipal create(User user, Map<String, Object> attributes) {
        UserPrincipal userPrincipal = UserPrincipal.create(user);
        userPrincipal.setAttributes(attributes);
        return userPrincipal;
    }

    public static UserPrincipal of(long seq, String id, String name) {
        return new UserPrincipal(seq, id, name, null);
    }

    @Override
    public String getUsername() { return id; }

    @Override
    public String getName() { return name; }

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
