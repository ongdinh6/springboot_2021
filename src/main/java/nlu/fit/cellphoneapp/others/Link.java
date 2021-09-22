package nlu.fit.cellphoneapp.others;

import org.springframework.context.annotation.Bean;

import javax.servlet.http.HttpServletRequest;

public class Link {
    public static final String HOST = "https://st5group08.000webhostapp.com/";

    public static String createAbsolutePath(HttpServletRequest request, String relativePath) {
        return "http://" + request.getServerName() + ":" + request.getServerPort()
                + request.getContextPath() + relativePath;
    }
}
