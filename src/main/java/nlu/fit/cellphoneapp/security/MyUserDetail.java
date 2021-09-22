package nlu.fit.cellphoneapp.security;

import lombok.Getter;
import nlu.fit.cellphoneapp.entities.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Collection;

@Getter
public class MyUserDetail extends org.springframework.security.core.userdetails.User {
    User user;

    public MyUserDetail(nlu.fit.cellphoneapp.entities.User user, String username, String password, Collection<? extends GrantedAuthority> authorities) {
        super(username, password, authorities);
        this.user = user;
    }

    public MyUserDetail(String username, String password, boolean enabled, boolean accountNonExpired, boolean credentialsNonExpired, boolean accountNonLocked, Collection<? extends GrantedAuthority> authorities) {
        super(username, password, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities);
    }

    public static MyUserDetail getPrincipal() {
        try {
            return (MyUserDetail) (SecurityContextHolder.getContext()).getAuthentication().getPrincipal();
        } catch (Exception e) {
            return null;
        }
    }

    public static User getUserIns() {
        if(getPrincipal() == null) return null;
        return getPrincipal().getUser();
    }

}
