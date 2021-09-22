package nlu.fit.cellphoneapp.security;
import nlu.fit.cellphoneapp.entities.User;
import nlu.fit.cellphoneapp.services.IUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class MyAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    @Autowired
    IUserService userService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        response.setStatus(HttpServletResponse.SC_ACCEPTED);
        User user = userService.findOneByEmail(authentication.getName());
        System.out.println("USER_ROLE = "+user.getActive());
        if(user.getActive() == 0) {
            response.getWriter().print("blocked"); 
            response.getWriter().flush();
        }else{
            response.getWriter().print("success");
            response.getWriter().flush();
        }
    }
}
