package bg.rumbata.security_presentation.repository;

import bg.rumbata.security_presentation.model.MobileUser;
import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

@Repository
public class MobileUserRepository {

    private final Map<String, MobileUser> users = new LinkedHashMap<>();

    public MobileUserRepository() {
        save(new MobileUser("request-mobile", "1234", "John", "Doe", new ArrayList<>()));
    }

    public Optional<MobileUser> findByUsername(String username) {
        return Optional.ofNullable(users.get(username));
    }

    public MobileUser save(MobileUser user) {
        users.put(user.getUsername(), user);
        return user;
    }
}
