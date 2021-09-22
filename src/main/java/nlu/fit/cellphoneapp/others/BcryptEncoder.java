package nlu.fit.cellphoneapp.others;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

public class BcryptEncoder {
    private static final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    private BcryptEncoder() {
    }

    public static PasswordEncoder getInstance() {
        return encoder;
    }

    public static String encode(String input) {
        return encoder.encode(input);
    }

    public static boolean matches(String firstInput, String secInput) {
        return encoder.matches(firstInput, secInput);
    }
}
