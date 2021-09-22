package nlu.fit.cellphoneapp.controllers.admin;

import nlu.fit.cellphoneapp.DTOs.UserDTO;
import nlu.fit.cellphoneapp.entities.User;
import nlu.fit.cellphoneapp.security.MyUserDetail;
import nlu.fit.cellphoneapp.services.IUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

import java.awt.print.Pageable;

@Controller("amdinUserManagement")
@RequestMapping("/admin/users-manage")
public class UserController {
    @Autowired
    private IUserService userService;

    @GetMapping
    public ModelAndView getAllUsers() {
        ModelAndView mv = new ModelAndView("admin/admin-user-management");
        mv.addObject("users", userService.getAllListUser());
        return mv;
    }
    @PutMapping("block/{id}")
    @ResponseBody
    public String blockUserAccount(@PathVariable("id") int id){
        User user = userService.findOneById(id);
        if(null == user) return "error";
        if(user.getActive() == 1) {
            user.setActive(0);
        }else{
            user.setActive(1);
        }
        userService.save(user);
        return "success";
    }
    @PostMapping("new")
    @ResponseBody
    public ResponseEntity<UserDTO> createNewUser(@RequestBody UserDTO userNew){

        if(null == userNew.getFullName() || userNew.getFullName()=="") return new ResponseEntity<UserDTO>(new UserDTO(), HttpStatus.BAD_REQUEST);
        if(userService.findOneByEmail(userNew.getEmailAddress())!=null) return new ResponseEntity<UserDTO>(new UserDTO(), HttpStatus.BAD_REQUEST);

        return new ResponseEntity<>(userNew, HttpStatus.OK);
    }
    @PostMapping("edit/{id}")
    @ResponseBody
    public ResponseEntity<UserDTO> editAUser(@PathVariable("id") int id, @RequestBody UserDTO user){
        User userEntity = userService.findOneById(id);

        System.out.println("user = "+user.toString());
        if(null==userEntity) return new ResponseEntity<UserDTO>(new UserDTO(), HttpStatus.BAD_REQUEST);
        userService.save(userEntity);

        return new ResponseEntity<>(user, HttpStatus.OK);
    }

    @PutMapping("/{id}")
    @ResponseBody
    public ResponseEntity<?> changeRoleUser(@PathVariable int id, int role){
        User user = userService.findOneById(id);
        if(role == 1){
            user.setRole(1);
        }else{
            user.setRole(2);
        }
        userService.save(user);
        return new ResponseEntity<>("Thay đổi thành công quyền truy cập người dùng!", HttpStatus.OK);
    }

}
