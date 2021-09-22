package nlu.fit.cellphoneapp.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;

@SpringBootApplication
public class EmailSenderService {
    @Autowired
    JavaMailSender mailSender;

    public String createBodyVertifyEmail(String name, String url) {
        String body = "<p>Chào " + name + ",</p>" + "<p>Nhấn vào link bên dưới để xác nhận email.</p>" + "<a href=" + url + " >CLICK VÀO ĐÂY</a>"
                + "<p>Nếu bạn không xác nhận sau 15 phút thì đường link bên trên sẽ bị hủy.<p>" + "<p>Chúc bạn một ngày vui vẻ<./p>" + "<p>DHMOBILE</p>";
        return body;
    }

    public String createBodyResetPassword(String name, String token) {
        String body = "<p>Chào " + name + ",</p>" + "<p>Bạn đã yêu cầu hồi phục mật khảu</p>" + "<p><span style=\"font-weight: bold;\">" + "Mã code: " +
                "</span>" + token + "</p>" + "<p>Mã code trên sẽ bị hủy sau 15 phút.<p>" + "<p>Chúc bạn một ngày vui vẻ.</p>" + "<p>DHMOBILE</p>";
        return body;
    }

    public boolean sendEmailResetPassword(String recipient, String name, String token) {
        return sendEmail(recipient, createBodyResetPassword(name, token), "Reset Mật Khẩu");
    }

    public boolean sendEmailVertification(String recipient, String name, String url) {
        return sendEmail(recipient, createBodyVertifyEmail(name, url), "Xác Nhận Địa Chỉ Email");
    }

    public boolean sendEmail(String recipient, String body, String subject) {
        try {
            MimeMessage msg = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(msg, true);
            helper.setFrom("ongdinh1099@gmail.com", "DHMOBILE");
            helper.setTo(recipient);
            helper.setSubject(subject);
            helper.setText(body, true);
            mailSender.send(msg);
            return true;
        } catch (Exception e) {
            System.out.println(e.getMessage());
            return false;
        }
    }
}
