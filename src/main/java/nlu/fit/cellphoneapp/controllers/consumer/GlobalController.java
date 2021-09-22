package nlu.fit.cellphoneapp.controllers.consumer;

import nlu.fit.cellphoneapp.entities.Brand;
import nlu.fit.cellphoneapp.entities.Pin;
import nlu.fit.cellphoneapp.entities.Ram;
import nlu.fit.cellphoneapp.entities.Rom;
import nlu.fit.cellphoneapp.services.IBrandService;
import nlu.fit.cellphoneapp.services.IPinService;
import nlu.fit.cellphoneapp.services.IRamService;
import nlu.fit.cellphoneapp.services.IRomService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import javax.validation.ConstraintViolation;
import javax.validation.ConstraintViolationException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@ControllerAdvice(basePackages = "nlu.fit.cellphoneapp.controllers")
public class GlobalController extends ResponseEntityExceptionHandler {
    @Autowired
    IBrandService brandService;
    @Autowired
    IPinService pinService;
    @Autowired
    IRomService romService;
    @Autowired
    IRamService ramService;
    @ModelAttribute("allBrands")
    public List<Brand> allBrands() {
        return brandService.findAllByActive(1);
    }
    @ModelAttribute("allRams")
    public List<Ram> allRams() {
        return ramService.findAllByActive(1);
    }

    @ModelAttribute("allRoms")
    public List<Rom> allRoms() {
        return romService.findAllByActive(1);
    }

    @ModelAttribute("allPins")
    public List<Pin> allPins() {
        return pinService.findAllByActive(1);
    }
    @ExceptionHandler(ConstraintViolationException.class)
    @ResponseBody
    protected ResponseEntity<Object> handleConstraint(ConstraintViolationException e,
                                                      WebRequest request) {
        System.out.println("that");

        Map<String, String> error = new HashMap<>();
        for (ConstraintViolation violation : e.getConstraintViolations()) {
            error.put(violation.getPropertyPath().toString(), violation.getMessageTemplate());
        }
        return ResponseEntity.ok().body(error);
    }

//    @Override
//    protected ResponseEntity handleMethodArgumentNotValid(MethodArgumentNotValidException e, WebRequest request) {
//        Map<String, String> error = new HashMap<>();
//        for (ObjectError objectError : e.getAllErrors()) {
//            String fieldErrors = ((FieldError) objectError).getField();
//            error.put(fieldErrors, objectError.getCode());
//        }
//        return ResponseEntity.ok().body(error);
//    }

    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException e, HttpHeaders headers, HttpStatus status, WebRequest request) {
        Map<String, String> error = new HashMap<>();
        for (ObjectError objectError : e.getAllErrors()) {
            String fieldErrors = ((FieldError) objectError).getField();
            error.put(fieldErrors, objectError.getDefaultMessage());
        }
        return ResponseEntity.ok().body(error);
    }
}
