package nlu.fit.cellphoneapp.controllers.consumer;

import nlu.fit.cellphoneapp.DTOs.CustomResponseCart;
import nlu.fit.cellphoneapp.entities.CartItem;
import nlu.fit.cellphoneapp.entities.Order;
import nlu.fit.cellphoneapp.entities.OrderDetail;
import nlu.fit.cellphoneapp.entities.User;
import nlu.fit.cellphoneapp.security.MyUserDetail;
import nlu.fit.cellphoneapp.services.ICartService;
import nlu.fit.cellphoneapp.services.IOrderDetailService;
import nlu.fit.cellphoneapp.services.IOrderService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpSession;
import java.util.Date;

@Controller
public class OrderController {

    public static int oi = 0;

    @Autowired
    IOrderService orderService;
    @Autowired
    ICartService cartService;
    @Autowired
    IOrderDetailService orderDetailService;

    @GetMapping("/order")
    public String goToOrderPage(HttpSession session, Model model) {
        User userDelivery;
        if ((null != (userDelivery = (User) model.getAttribute("userDelivery")) && userDelivery.getCartItems().size() == 0) || null == userDelivery) {
            return "redirect:/cart";
        }
        if (null == session.getAttribute(User.SESSION)) return "redirect:/home";
        return "order";
    }

    @PostMapping("/order")
    @ResponseBody
    public String ajaxSendDataOrder(String address, String nameClient, String phoneNumber, double totalPrice, String payment, String paypalResponse, HttpSession session) {
        Order order = new Order();
        Date createDate = new Date();
        createDate.setTime(System.currentTimeMillis());
        order.setCreatedDate(createDate);
        order.setAddress(address);
        order.setActive(1);
        order.setNameOfClient(nameClient);
        order.setPhoneNumberOfClient(phoneNumber);
        order.setTotalPrice(totalPrice);
        User user = MyUserDetail.getUserIns();
        if (null != user) {
            System.out.println("");
            order.setUser(user);
            user.setFullName(nameClient);
            user.setAddress(address);
            user.setPhone(phoneNumber);
            session.setAttribute(User.SESSION, user);
            session.setAttribute("cartSession", null);
        }else{
            return "/login";
        }
        order.setOrderStatus("Đang tiếp nhận");
        order.setPayment(payment);

        Order order1 = null;
        if (!paypalResponse.equals("success")) {
            order1 = orderService.insertIntoTable(order);
            oi = order1.getId();
        } else {
            user.getOrders().add(orderService.getOne(oi));
            for (Order o : user.getOrders()) {
                cartService.removeAllByUserId(user.getId());
                user.getCartItems().clear();
                if (o.getId() == oi) {
                    o.setPayment("Online");
                    o.setActive(1);
                    orderService.updatePayment(o.getId(), "Online");
                    //cap nhat order detail co order id thanh active
                    orderDetailService.updateActive(o, 1);
                    CustomResponseCart.clearCart();
                    session.setAttribute("cartSession", null);
                }
            }
        }
        if (null != order1) {
            if (!payment.equals("Paypal")) {
                order.setActive(1);
            } else {
                order.setActive(0);
            }
            for (CartItem c : order.getUser().getCartItems()) {
                OrderDetail orderDetail = new OrderDetail();
                orderDetail.setOrder(order);
                orderDetail.updateSalePrice(0.0);
                orderDetail.setActive(0);
                orderDetail.setAmount(c.getAmount());
                orderDetail.setInitialPrice(c.getProduct().getPrice() * c.getAmount());
                orderDetail.setProduct(c.getProduct());
                orderDetail.setPrice(c.getProduct().getPrice());
                orderDetail.updateTotalPrice();
                OrderDetail orderDetail1 = orderDetailService.insertIntoTable(orderDetail);
                order.getOrderDetails().add(orderDetail1);
            }
            boolean removed = false;
            //cho cancel paypal
            if (!payment.equals("Paypal")) {
                orderDetailService.updateActive(order, 1);
                removed = cartService.removeAllByUserId(user.getId());
                user.getCartItems().clear();
                user.getOrders().add(order);
                CustomResponseCart.clearCart();
                return "/user/my-order";
            } else {
                return "/pay";
            }
        } else {
            return "error";
        }
    }

    @PostMapping("/ajax-deny-order")
    public @ResponseBody
    String ajaxDenyOrder(int orderID, HttpSession session) {
        System.out.println("DenyOrder id = " + orderID);
        User user = (User) session.getAttribute(User.SESSION);
        for (Order o : user.getOrders()) {
            if (o.getId() == orderID && o.getOrderStatus().equals("Đang tiếp nhận")) {
                o.setOrderStatus("Đã hủy");
                orderService.updateOrderStatus(o);
                System.out.println("Hủy thành công đơn hàng " + orderID);
                return "Hủy thành công!";
            }
        }
        return "error";
    }

}