package nlu.fit.cellphoneapp.controllers.admin;


import nlu.fit.cellphoneapp.entities.Order;
import nlu.fit.cellphoneapp.services.IOrderService;
import org.hibernate.annotations.Parameter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

import java.util.List;

@Controller("adminOrderController")
@RequestMapping("/admin/orders-manage")
public class OrderController {
    @Autowired
    private IOrderService orderService;

    @GetMapping("pending")
    public ModelAndView getListPendingOrder(){
        ModelAndView mv = new ModelAndView("admin/admin-order-pending-management");
        List<Order> listOrderPending = orderService.listOrderByStatus("Đang tiếp nhận");
        mv.addObject("orders", listOrderPending);
        return mv;
    }
    @GetMapping("delivering")
    public ModelAndView getListDeliveringOrder(){
        ModelAndView mv = new ModelAndView("admin/admin-order-delivering-management");
        mv.addObject("orders", orderService.listOrderByStatus("Đang giao hàng"));
        return mv;
    }
    @GetMapping("finish")
    public ModelAndView getListFinishOrder(){
        ModelAndView mv = new ModelAndView("admin/admin-order-finish-management");
        mv.addObject("orders", orderService.listOrderByStatus("Giao thành công"));
        return mv;
    }
    @GetMapping("deny")
    public ModelAndView getListDenyOrder(){
        ModelAndView mv = new ModelAndView("admin/admin-order-deny-management");
        mv.addObject("orders", orderService.listOrderByStatus("Đã hủy"));
        return mv;
    }
    @PutMapping("pending/{id}")
    @ResponseBody
    public String acceptOrder(@PathVariable("id") int id, @RequestHeader(required = false, defaultValue = "null") String action){
        Order order = orderService.getOne(id);
        if(null == order) return "error";
        order.setOrderStatus("Đang giao hàng");
        if(action.equals("refuse")) order.setOrderStatus("Đã hủy");
        orderService.insertIntoTable(order);
        return "success";
    }

    @GetMapping("order-detail")
    public ModelAndView goToDetailOrderPage(@Param("id") int id){
        ModelAndView mv = new ModelAndView("admin/order-detail");
        Order order = orderService.getOne(id);
        if(null == order) return null;
        mv.addObject("order", order);
        return mv;
    }

    @PutMapping("delivering/{id}")
    @ResponseBody
    public String finishOrderDelivering(@PathVariable int id){
        System.out.println("ID REQUEST = "+id);
        Order order;
        if(null == (order = orderService.getOne(id)))
            return "fail";
        order.setOrderStatus(Order.STATUS.SUCCESS.value());
        orderService.insertIntoTable(order);
        return "success";
    }

}
