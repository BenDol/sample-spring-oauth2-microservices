package pl.piomin.services.auth.tmp;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.resource.PrincipalExtractor;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import pl.piomin.services.auth.domain.User;

import java.util.Map;

@Component
public class UserPrincipalExtractor implements PrincipalExtractor {

    @Autowired @Lazy
    private UserDetailsService userDetailsService;

    @Override
    public Object extractPrincipal(Map<String, Object> details) {
        String email = (String) details.get("email");
        UserDetails user = userDetailsService.loadUserByUsername(email);
        return user != null ? extractDetails(user, details) : null;
    }

    private UserDetails extractDetails(UserDetails user, Map<String, Object> details) {
        // Google specific user details
        try {
            /*user.setName((String) details.get("name"));
            user.setGivenName((String) details.get("given_name"));
            user.setFamilyName((String) details.get("family_name"));
            user.setLocale((String) details.get("locale"));
            user.setEmailVerified((Boolean) details.get("email_verified"));
            user.setGender((String) details.get("gender"));
            user.setPicture((String) details.get("picture"));*/
        } catch (Exception ex) {
            //logger.debug("Detail extraction caused an exception: " + ex.getMessage());
        }
        return user;
    }
}