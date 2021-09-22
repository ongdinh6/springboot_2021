package nlu.fit.cellphoneapp.validator;

import nlu.fit.cellphoneapp.entities.User;
import nlu.fit.cellphoneapp.helper.DateHelper;
import nlu.fit.cellphoneapp.helper.StringHelper;
import nlu.fit.cellphoneapp.receiver.UpdateInfoForm;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
import java.util.Date;

public class UpdateInfoValidator implements ConstraintValidator<ValidUpdateInfo, UpdateInfoForm> {
    @Override
    public void initialize(ValidUpdateInfo constraintAnnotation) {

    }

    @Override
    public boolean isValid(UpdateInfoForm form, ConstraintValidatorContext context) {
        boolean isValid = true;
        if (StringHelper.EmptyOrWhitespace(form.fullName)) {
            isValid = false;
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate("Họ và tên của bạn không được để trống")
                    .addPropertyNode("fullName")
                    .addConstraintViolation();
        } else {
            if (!User.validName(form.fullName)) {
                isValid = false;
                context.disableDefaultConstraintViolation();
                context.buildConstraintViolationWithTemplate("Họ và tên của bạn không hợp lệ")
                        .addPropertyNode("fullName")
                        .addConstraintViolation();
            }
        }
        if (!StringHelper.EmptyOrWhitespace(form.phone)) {
            if (!User.validPhone(form.phone)) {
                isValid = false;
                context.disableDefaultConstraintViolation();
                context.buildConstraintViolationWithTemplate("Số điện thoại không hợp lệ")
                        .addPropertyNode("phone")
                        .addConstraintViolation();
            }
        }
        if (!StringHelper.EmptyOrWhitespace(form.address)) {
            if (form.address.length() < 10) {
                isValid = false;
                context.disableDefaultConstraintViolation();
                context.buildConstraintViolationWithTemplate("Địa chỉ phải có ít nhất 10 ký tự")
                        .addPropertyNode("address")
                        .addConstraintViolation();
            }
        }
        if (!StringHelper.EmptyOrWhitespace(form.birth)) {
            Date birth = DateHelper.convertToDate(form.birth, "yyyy-MM-dd");
            if (birth == null) {
                isValid = false;
                context.disableDefaultConstraintViolation();
                context.buildConstraintViolationWithTemplate("Ngày sinh của bạn không hợp lệ")
                        .addPropertyNode("birth")
                        .addConstraintViolation();
            } else {
                if (!birth.before(new Date())) {
                    isValid = false;
                    context.disableDefaultConstraintViolation();
                    context.buildConstraintViolationWithTemplate("Ngày sinh của bạn phải nhỏ hơn ngày hôm nay")
                            .addPropertyNode("birth")
                            .addConstraintViolation();
                }
            }
        }
        if (StringHelper.EmptyOrWhitespace(form.gender)) {
            isValid = false;
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate("Giới tính của bạn không được để trống")
                    .addPropertyNode("gender")
                    .addConstraintViolation();
        } else {
            if (!User.validGender(form.gender)) {
                context.disableDefaultConstraintViolation();
                context.buildConstraintViolationWithTemplate("Giới tính của bạn không hợp lệ")
                        .addPropertyNode("gender")
                        .addConstraintViolation();
            }
        }
        return isValid;
    }
}
