package pl.piomin.services.auth.tmp;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.resource.AuthoritiesExtractor;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import pl.piomin.services.auth.domain.User;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Component
public class UserAuthoritiesExtractor implements AuthoritiesExtractor {

    @Autowired @Lazy
    private UserDetailsService userDetailsService;

    @Override
    public List<GrantedAuthority> extractAuthorities(Map<String, Object> map) {
        UserDetails user = userDetailsService.loadUserByUsername((String)map.get("email"));
        if (user != null) {
            List<String> roles = new ArrayList<>();
            //roles.add(UserRole.NAME);

            /*for (Role role : user.getRoles()) {
                if(!roles.contains(role.getName())) {
                    roles.add(role.getName());
                }
            }*/
            return AuthorityUtils.createAuthorityList(roles.toArray(new String[0]));
        }
        return null;
    }
}
