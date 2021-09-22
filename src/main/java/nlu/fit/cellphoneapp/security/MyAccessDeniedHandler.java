package nlu.fit.cellphoneapp.security;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
@Component
public class MyAccessDeniedHandler implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException e) throws IOException, ServletException {
        System.out.println("denied");
        if (request.getMethod().equals(RequestMethod.GET.name())) {
            response.sendRedirect(request.getContextPath() + "/");
        } else {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        }
    }
}
