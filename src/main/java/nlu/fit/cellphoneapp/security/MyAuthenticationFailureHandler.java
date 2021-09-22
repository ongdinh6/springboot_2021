package nlu.fit.cellphoneapp.security;

import nlu.fit.cellphoneapp.entities.User;
import nlu.fit.cellphoneapp.services.IUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class MyAuthenticationFailureHandler implements AuthenticationFailureHandler {
    @Autowired
    IUserService userService;
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        response.setStatus(HttpServletResponse.SC_ACCEPTED);
        String ex = request.getParameter("email");
        User user = userService.findOneByEmail(ex);
        System.out.println(user.getPassword());
        if(userService.findOneByEmail(ex) != null && userService.findOneByEmail(ex).getActive() == 0) {
            response.getWriter().print("blocked");
            response.getWriter().flush();
        }else {
            response.getWriter().print("failed");
            response.getWriter().flush();
        }
    }
}
