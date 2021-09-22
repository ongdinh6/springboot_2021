package nlu.fit.cellphoneapp.DTOs;

public class CheckoutForm {
    private String fullName;
    private String phone;
    private String address;
    private String province;
    private String district;
    private String award;
    private String detail;

    public String getFullName() {
        return fullName;
    }

    public void setFullName(String fullName) {
        this.fullName = fullName;
    }

    public String getPhone() {
        return phone;
    }

    public void setPhone(String phone) {
        this.phone = phone;
    }

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }

    public String getProvince() {
        return province;
    }

    public void setProvince(String province) {
        this.province = province;
    }

    public String getDistrict() {
        return district;
    }

    public void setDistrict(String district) {
        this.district = district;
    }

    public String getAward() {
        return award;
    }

    public void setAward(String award) {
        this.award = award;
    }

    public String getDetail() {
        return detail;
    }

    public void setDetail(String detail) {
        this.detail = detail;
    }

    public CheckoutForm(String fullName, String phone, String address) {
        this.fullName = fullName;
        this.phone = phone;
        this.address = address;
        setInfoAddress();
    }

    public CheckoutForm() {
    }

    public void setInfoAddress() {
        String[] all = address.split(", ");
        this.province = all[all.length - 1];
        this.district = all[all.length - 2];
        this.award = all[all.length - 3];

        for (int i = 0; i < all.length - 3; i++) {
            this.detail += all[i];
        }
    }

}
