package nlu.fit.cellphoneapp.helper;

import org.springframework.web.multipart.MultipartFile;

import javax.servlet.ServletContext;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.Date;

public class UploadFileHelper {

    public static  String upload(MultipartFile multipartFile, ServletContext servletContext){
        try{
            SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyyMMddHHmmss");
            String fileName = simpleDateFormat.format(new Date())+multipartFile.getOriginalFilename();
            Path path = Paths.get(servletContext.getRealPath("/images/"+fileName));
            Files.write(path, multipartFile.getBytes());
            return fileName;
        }catch (Exception e){
            return null;
        }
    }
}
