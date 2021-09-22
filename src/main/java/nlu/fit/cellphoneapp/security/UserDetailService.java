package nlu.fit.cellphoneapp.security;

import nlu.fit.cellphoneapp.entities.User;
import nlu.fit.cellphoneapp.repositories.interfaces.IUserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

@Service
public class UserDetailService implements UserDetailsService {
    @Autowired
    private IUserRepository userRepository;

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepository.findOneLogin(email);
        if (user == null) {
            throw new UsernameNotFoundException("User not found.");
        } else {
            List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
            grantedAuthorities.add(new
                    SimpleGrantedAuthority(user.toStringRole()));
            MyUserDetail userDetail = new MyUserDetail(user, user.getEmail(), user.getPassword(), grantedAuthorities);
            return userDetail;
        }
    }
}
