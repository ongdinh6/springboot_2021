package nlu.fit.cellphoneapp.controllers.consumer;

import nlu.fit.cellphoneapp.entities.Order;
import nlu.fit.cellphoneapp.entities.User;
import nlu.fit.cellphoneapp.helper.DateHelper;
import nlu.fit.cellphoneapp.helper.StringHelper;
import nlu.fit.cellphoneapp.others.BcryptEncoder;
import nlu.fit.cellphoneapp.others.Link;
import nlu.fit.cellphoneapp.security.MyUserDetail;
import nlu.fit.cellphoneapp.receiver.UpdateInfoForm;
import nlu.fit.cellphoneapp.receiver.UpdatePasswordForm;
import nlu.fit.cellphoneapp.services.EmailSenderService;
import nlu.fit.cellphoneapp.services.ICartService;
import nlu.fit.cellphoneapp.services.IOrderService;
import nlu.fit.cellphoneapp.services.IUserService;
import nlu.fit.cellphoneapp.validator.ValidUpdateInfo;
import nlu.fit.cellphoneapp.validator.UpdatePasswordValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.Errors;
import org.springframework.validation.FieldError;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.validation.Valid;
import java.io.IOException;
import java.util.Collection;
import java.util.HashSet;
import java.util.HashMap;
import java.util.Map;

import static nlu.fit.cellphoneapp.security.MyUserDetail.getUserIns;

@Controller
@RequestMapping(value = "/user")
public class UserController {
    @Autowired
    IUserService userService;
    @Autowired
    EmailSenderService emailSenderService;
    @Autowired
    ICartService cartService;
    @Autowired
    UpdatePasswordValidator updatePasswordValidator;
    @Autowired
    IOrderService orderService;

    @RequestMapping(value = "", method = RequestMethod.GET)
    public ModelAndView myAccountPage() {
        User user = getUserIns();
        ModelAndView model = new ModelAndView("/consumer/my-account");
        model.addObject("CONTENT_TITLE", "Tài Khoản Của Tôi");
        if (user.getActive() == User.ACTIVE.UNVERTIFIED.value()) {
            model.addObject("NO_ACTIVE", true);
        }
        return model;
    }

    @RequestMapping(value = "/email/verify/{token}")
    public ModelAndView vertificateEmail(@PathVariable("token") String token) {
        User u;
        if ((u = userService.findOneByToken(token)) == null)
            return new ModelAndView("redirect:/");
        else {
            u.setKey(null);
            u.setExpiredKey(null);
            u.setActive(User.ACTIVE.ACTIVE.value());
            User user = getUserIns();
            user.setKey(null);
            user.setExpiredKey(null);
            user.setActive(User.ACTIVE.ACTIVE.value());
            if (!userService.save(u)) {
                return new ModelAndView("redirect:/");
            }
            return new ModelAndView("/consumer/email-vertification");
        }
    }


    @RequestMapping(value = "request-vertify-email", method = RequestMethod.POST)
    @ResponseBody
    public String requestVerityEmail(HttpServletRequest request) {
        User user = getUserIns();
        String token;
        while (userService.isTokenUnique((token = StringHelper.getAlphaNumericString(50)))) ;
        user.setKey(token);
        user.setExpiredKey(DateHelper.addMinute(15));
        if (!userService.save(user)) {
            return "error";
        } else if (!emailSenderService.sendEmailVertification(user.getEmail(), user.getFullName(), Link.createAbsolutePath(request, "/user/email/verify/" + token))) {
            return "errsendmail";
        } else {
            return "success";
        }
    }

    @RequestMapping(value = "update-password", method = RequestMethod.GET)
    public ModelAndView updatePasswordPage() {
        ModelAndView model = new ModelAndView("/consumer/update-password");
        model.addObject("CONTENT_TITLE", "Đổi Mật Khẩu");
        return model;
    }

    @RequestMapping(value = "update-password", method = RequestMethod.POST)
    @ResponseBody
    public ResponseEntity updatePassword(@RequestBody UpdatePasswordForm form, Errors errors) {
        updatePasswordValidator.validate(form, errors);
        if (errors.hasErrors()) {
            Map<String, String> errMessages = new HashMap<>();
            for (ObjectError objectError : errors.getAllErrors()) {
                String fieldErrors = ((FieldError) objectError).getField();
                errMessages.put(fieldErrors, objectError.getCode());
            }
            return ResponseEntity.ok().body(errMessages);
        } else {
            User user = getUserIns();
            user.setPassword(BcryptEncoder.encode(form.newPassword));
            if (userService.save(user)) {
                return ResponseEntity.ok(HttpStatus.ACCEPTED);
            } else {
                return ResponseEntity.ok().body("failed");
            }
        }
    }

    @RequestMapping(value = "update-infor", method = RequestMethod.GET)
    public ModelAndView updateInforPage() {
        ModelAndView model = new ModelAndView("/consumer/update-infor");
        model.addObject("CONTENT_TITLE", "Cập Nhật Thông Tin Cá Nhân");
        return model;
    }

    @RequestMapping(value = "update-infor", method = RequestMethod.POST)
    public ResponseEntity updateInfor(@Valid @RequestBody UpdateInfoForm form) {
        User user = getUserIns();
        user.updateInfo(form);
        if (userService.save(user)) {
            return ResponseEntity.ok(HttpStatus.ACCEPTED);
        } else {
            return ResponseEntity.ok().body("failed");
        }
    }

    //UserMyAccountManage
    @GetMapping("my-order")
    public String goToMyOrderManagementPage(Model model) {
        model.addAttribute("CONTENT_TITLE", "Quản lý đơn hàng");
        if (null == MyUserDetail.getUserIns()) {
            return "consumer/my-order-empty";
        } else {
            User user = MyUserDetail.getUserIns();
            Collection<Order> collectionOrderUserDB = orderService.getListOrderOfUser(user.getId());
            user.checkAndSetOrderUserDB(collectionOrderUserDB);
            if(user.getOrders().size() == 0) return "consumer/my-order-empty";
            model.addAttribute("orders", user.getOrders());
            return "consumer/my-order";
        }
    }


}