package nlu.fit.cellphoneapp.receiver;

import lombok.Getter;
import lombok.Setter;
import nlu.fit.cellphoneapp.validator.ValidUpdateInfo;

@Getter
@Setter
@ValidUpdateInfo
public class UpdateInfoForm {
    public String fullName;
    public String birth;
    public String address;
    public String phone;
    public String gender;
}
