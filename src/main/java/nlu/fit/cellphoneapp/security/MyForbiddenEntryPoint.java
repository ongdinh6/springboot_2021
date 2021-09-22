package nlu.fit.cellphoneapp.security;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
@Component
public class MyForbiddenEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException, ServletException {
        if (request.getMethod().equals(RequestMethod.GET.name())) {
            response.sendRedirect(request.getContextPath() + "/");
        } else {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        }
    }
}
