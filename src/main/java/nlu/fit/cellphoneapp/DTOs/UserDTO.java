package nlu.fit.cellphoneapp.DTOs;

public class UserDTO {
    private String fullName;
    private String emailAddress;
    private String password;
    private int role;
    private int active;

    public String getFullName() {
        return fullName;
    }

    public void setFullName(String fullName) {
        this.fullName = fullName;
    }

    public String getEmailAddress() {
        return emailAddress;
    }

    public void setEmailAddress(String emailAddress) {
        this.emailAddress = emailAddress;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public int getRole() {
        return role;
    }

    public void setRole(int role) {
        this.role = role;
    }

    public int getActive() {
        return active;
    }

    public void setActive(int active) {
        this.active = active;
    }

    @Override
    public String toString() {
        return "{" +
                "\"fullName\":" + fullName  +
                ",\"emailAddress\":" + emailAddress +
                ", \"password\":" + password  +
                ", \"role\":" + role +
                ", \"active\"" + active +
                '}';
    }
}
