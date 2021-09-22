package nlu.fit.cellphoneapp.controllers.consumer;

import nlu.fit.cellphoneapp.DTOs.CartItemRequest;
import nlu.fit.cellphoneapp.DTOs.CheckoutForm;
import nlu.fit.cellphoneapp.DTOs.CustomResponseCart;
import nlu.fit.cellphoneapp.entities.CartItem;
import nlu.fit.cellphoneapp.entities.User;
import nlu.fit.cellphoneapp.helper.DateHelper;
import nlu.fit.cellphoneapp.helper.StringHelper;
import nlu.fit.cellphoneapp.others.BcryptEncoder;
import nlu.fit.cellphoneapp.receiver.RegisterForm;
import nlu.fit.cellphoneapp.security.MyUserDetail;
import nlu.fit.cellphoneapp.services.EmailSenderService;
import nlu.fit.cellphoneapp.services.ICartService;
import nlu.fit.cellphoneapp.services.IUserService;
import org.hibernate.annotations.Check;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.*;

@Controller("ConsumerHomeController")
public class HomeController {
    @Autowired
    ICartService cartService;
    @Autowired
    IUserService userService;
    @Autowired
    EmailSenderService emailSenderService;


    @GetMapping({"/", "/home"})
    public String getIndex(Model model, HttpSession session) {
        if (User.checkUserSession(session)) session.setAttribute("cartSession", new HashSet<CartItemRequest>());
        model.addAttribute("CONTENT_TITLE", "Trang chủ");
        session.setAttribute("cartOnSessionForCartControllerV2", new HashSet<CartItemRequest>());
        return "consumer/index";
    }

    @RequestMapping(value = "register", method = RequestMethod.POST)
    public @ResponseBody
    String register(@RequestBody RegisterForm form
    ) {
        String error = User.validInfo(form);
        if (error != null) {
            return error;
        } else if (!userService.isEmailUnique(form.newemail)) {
            return "errmailexist";
        } else {
            User user = new User();
            user.setEmail(form.newemail);
            user.setGender(User.toStringGender(Integer.parseInt(form.newgender)));
            user.setPassword(BcryptEncoder.encode(form.newpassword));
            user.setFullName(form.newfullname);
            user.setActive(User.ACTIVE.UNVERTIFIED.value());
            user.setRole(User.ROLE.CONSUMEER.value());
            if (!userService.save(user)) {
                return "error";
            } else {
                return "success";
            }
        }
    }

    //unblock account
    @RequestMapping(value = "/unblock-account", method = RequestMethod.POST)
    @ResponseBody
    public String unblockAccountRequest(String email) {
        System.out.println("EMAIL = " + email);
        User userRequest = userService.findOneByEmail(email);
        if (userRequest == null) return "noexistemail";
        if (userRequest.getActive() != 0 && userRequest.getActive() == 1) return "ready";
        if (userRequest.getActive() != 0 && userRequest.getActive() == -1) return "failedverify";
//        if(true == emailSenderService.sendEmail("ongdinh1099@gmail.com", "Hệ thống nhận được yêu cầu mở khóa tài khoản từ khách hàng có email là "+email+".\n<p> <a href=\"http://localhost:8080/admin/users-manage\">NHẤN VÀO ĐÂY ĐỂ TIẾN HÀNH MỞ KHÓA.</a></p>", "DH Mobile: YÊU CẦU MỞ KHÓA TÀI KHOẢN"))
//        {
        userRequest.setRequestUnblock(true);
        userService.save(userRequest);
        return "success";
//        }else{
//            return "failed";
//        }
    }

//    @ResponseBody
//    @RequestMapping(value = "/login", method = RequestMethod.POST)
//    public String login(@RequestParam(name = "email") String email, @RequestParam(name = "password") String password, HttpSession session) {
//        User user;
//        if (StringHelper.isNoValue(email) || StringHelper.isNoValue(password))
//            return "emptyfield";
//        else if ((user = userService.findOneByLogin(email, password)) != null) {
//            session.setAttribute(User.SESSION, user);
//            Set<CartItem> cartItems = (Set<CartItem>) session.getAttribute("cartSession");
//            Set<CartItem> cartItemsUser = user.getCartItems();
//            if (null != cartItems) {
//                //append cart session into user
//                CartItem[] cs = cartItems.toArray(new CartItem[cartItems.size()]);
//                //truoc khi append can lay cart User ra
//                if (cartItemsUser.size() > 0) {
//                    //duyet cart user
//                    for (int i = 0; i < cs.length; i++) {
//                        cs[i].setUser(user);
//                        for (CartItem c : cartItemsUser) {
//                            if (cs[i].getProduct().getId() == c.getProduct().getId()) {
//                                //không lưu vào user
//                                cs[i] = c;//gan cs[i] lai de luu csdl
//                            }
//                        }
//                        cartItemsUser.add(cs[i]);
//                        cartService.insertIntoTable(cs[i]);//luu lai vao csdl
//                    }
//                } else {
//                    for (CartItem c : cartItems) {
//                        c.setUser(user);
//                        cartItemsUser.add(c);
//                        cartService.insertIntoTable(c);
//                    }
//                }
//                session.setAttribute("cartSession", null);
//            }
//            return "success";
//        } else
//            return "failed";
//    }

    @RequestMapping(value = "/forgot-pass", method = RequestMethod.POST)
    public @ResponseBody
    String forgotPass(@RequestParam(name = "email") String email) {
        User user;
        if (StringHelper.isNoValue(email)) return "emptyfield";
        else if ((user = userService.findOneByEmailActive(email, User.ACTIVE.ACTIVE.value())) == null &&
                (user = userService.findOneByEmailActive(email, User.ACTIVE.UNVERTIFIED.value())) == null) {
            return "unactive";
        } else {
            String token;
            while (userService.isTokenUnique((token = StringHelper.getAlphaNumericString(10)))) ;
            user.setKey(token);
            user.setExpiredKey(DateHelper.addMinute(15));
            if (!userService.save(user)) {
                return "error";
            }
            if (emailSenderService.sendEmailResetPassword(email, user.getFullName(), token)) {
                return "success";
            } else
                return "failed";
        }

    }

    @RequestMapping(value = "/reset-pass", method = RequestMethod.POST)
    @ResponseBody
    public String resetPass(@RequestParam(name = "resetcode") String
                                    resetcode, @RequestParam(name = "newpass") String newpass, @RequestParam(name = "confirmpass") String
                                    confirmpass) {
        User user;
        List<String> toCheck = new ArrayList<>();
        toCheck.add(resetcode);
        toCheck.add(newpass);
        toCheck.add(confirmpass);
        if (StringHelper.isNoValue(toCheck)) {
            return "emptyfield";
        } else if (!User.validPassword(newpass))
            return "validpass";
        else if (!newpass.equals(confirmpass))
            return "notequate";
        else if ((user = userService.findOneByToken(resetcode)) == null) {
            return "failcode";
        } else {
            user.setPassword(BcryptEncoder.encode(newpass));
            user.setKey(null);
            user.setExpiredKey(null);
            if (!userService.save(user)) {
                return "error";
            }
            return "success";
        }
    }

    @GetMapping("/checkout")
    public ModelAndView goToCheckoutPage() {
        User user;
        ModelAndView mv = new ModelAndView("consumer/checkout");
        if (null != (user = MyUserDetail.getUserIns())) {
            CheckoutForm form = new CheckoutForm();
            form.setFullName(user.getFullName());
            mv.addObject("user", form);
            if (user.getActive() == -1) {
                mv.setViewName("consumer/active-account");
            } else {
                if (CustomResponseCart.isEmpty) {
                    mv.setViewName("consumer/cart");
                }
            }
        } else {
            if (CustomResponseCart.isEmpty) {
                mv.setViewName("consumer/cart");
            }
        }
        return mv;
    }


}
