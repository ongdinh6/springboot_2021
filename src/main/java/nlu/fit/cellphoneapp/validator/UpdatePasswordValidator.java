package nlu.fit.cellphoneapp.validator;

import nlu.fit.cellphoneapp.entities.User;
import nlu.fit.cellphoneapp.others.BcryptEncoder;
import nlu.fit.cellphoneapp.receiver.UpdatePasswordForm;
import nlu.fit.cellphoneapp.security.MyUserDetail;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.ValidationUtils;
import org.springframework.validation.Validator;

@Component
public class UpdatePasswordValidator implements Validator {

    @Override
    public boolean supports(Class<?> aClass) {
        return false;
    }

    @Override
    public void validate(Object o, Errors errors) {
        UpdatePasswordForm form = (UpdatePasswordForm) o;
        ValidationUtils.rejectIfEmptyOrWhitespace(errors, "oldPassword", "Bạn không thể để trống trường dữ liệu này");
        ValidationUtils.rejectIfEmptyOrWhitespace(errors, "newPassword", "Bạn không thể để trống trường dữ liệu này");
        ValidationUtils.rejectIfEmptyOrWhitespace(errors, "confirmPassword", "Bạn không thể để trống trường dữ liệu này");
        if (errors.getFieldError("oldPassword") == null) {
            if (!BcryptEncoder.matches(form.oldPassword, MyUserDetail.getUserIns().getPassword())) {
                errors.rejectValue("oldPassword", "Mật khẩu cũ không chính xác");
            }
        }
        if (errors.getFieldError("newPassword") == null) {
            if (!User.validPassword(form.newPassword)) {
                errors.rejectValue("newPassword", "Mật khẩu phải có ít nhất 8 ký tự, 1 ký tự thường, hoa , số, đặc biệt");
            }
        }
        if (errors.getFieldError("confirmPassword") == null) {
            if (!form.confirmPassword.equals(form.newPassword)) {
                errors.rejectValue("confirmPassword", "Xác nhận mật khẩu không trừng khớp với mật khẩu mới");
            }
        }
    }
}
