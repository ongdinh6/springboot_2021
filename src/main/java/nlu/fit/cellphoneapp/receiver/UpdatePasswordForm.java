package nlu.fit.cellphoneapp.receiver;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UpdatePasswordForm {
    public String oldPassword;
    public String newPassword;
    public String confirmPassword;
}
