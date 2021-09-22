package nlu.fit.cellphoneapp.controllers.consumer;

import nlu.fit.cellphoneapp.DTOs.CartItemRequest;
import nlu.fit.cellphoneapp.DTOs.CustomResponseCart;
import nlu.fit.cellphoneapp.DTOs.CustomResponseOrder;
import nlu.fit.cellphoneapp.entities.CartItem;
import nlu.fit.cellphoneapp.entities.Order;
import nlu.fit.cellphoneapp.entities.OrderDetail;
import nlu.fit.cellphoneapp.entities.User;
import nlu.fit.cellphoneapp.helper.NumberHelper;
import nlu.fit.cellphoneapp.helper.StringHelper;
import nlu.fit.cellphoneapp.others.Link;
import nlu.fit.cellphoneapp.security.MyUserDetail;
import nlu.fit.cellphoneapp.services.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;

@Controller
@RequestMapping("/api/order")
public class OrderControllerVer2 {
    public static Order orderPayPal;
    @Autowired
    IOrderService orderService;
    @Autowired
    IOrderDetailService orderDetailService;
    @Autowired
    IProductService productService;
    @Autowired
    ICartService cartService;
    @Autowired
    IUserService userService;
    @Autowired
    EmailSenderService emailSenderService;

    @PostMapping
    @ResponseBody
    public CustomResponseOrder createdNewOrder(@RequestBody Order orderInfo, @RequestHeader(required = false, value = "paypalSuccess") String paypalSuccess) {
        User user = MyUserDetail.getUserIns();
        if (null == user) {
            return new CustomResponseOrder();
        }
        Order order;
        if (orderInfo.getPayment().equals("cash")) {
            order = orderByCash(orderInfo);
        } else {
            if (paypalSuccess.equals("success")) {
                order = orderByPayPal(orderPayPal);
            } else {
                return null;
            }
        }
        //insertIntoTable
        order.setUser(user);
        order.setCreatedDate(new Date());
        order.setActive(1);
        order.setOrderDetails(createdOrderDetail(order));
        order = orderService.insertIntoTable(order);
        boolean insertedDetail = insertDBOrderDetail(order);
        if (insertedDetail == false) return null;
        //response
        CustomResponseOrder orderResponse = new CustomResponseOrder();
        orderResponse.setStatus(order.getOrderStatus());
        orderResponse.setActive(order.getActive());
        orderResponse.setListOrders(CustomResponseCart.cloneCart());
        orderResponse.setAmountItems(order.getOrderDetails().size());
        orderResponse.updateTotalAll();
        orderResponse.updateLastPrice();
        orderResponse.setId(order.getId());
        orderResponse.setName(order.getNameOfClient());
        orderResponse.setAddress(order.getAddress());
        orderResponse.setPayment(order.getPayment());
        orderResponse.setPhone(order.getPhoneNumberOfClient());
        DateFormat inputFormatter = new SimpleDateFormat("dd/MM/yyyy");
        orderResponse.setCreatedDate(inputFormatter.format(new Date()));


        for (CartItem c : user.getCartItems()) {
            cartService.deleteOne(c.getId());
        }
        user.getOrders().add(order);
        CustomResponseCart.clearCart();
        user.getCartItems().clear();

        StringBuilder body = new StringBuilder();
        body.append("<p>Vừa nhận được yêu cầu tiếp nhận đơn hàng từ hệ thống!</p>");
        body.append("<p>Đơn hàng có mã "+ order.getId()+", bao gồm: "+ order.getOrderDetails().size() +" sản phẩm.</p>");
        body.append("<p>Tổng tiền đơn hàng là: "+ StringHelper.formatNumber((long) order.getTotalPrice())+"VNĐ .</p>");
        body.append("<a href=\"http://localhost:8080/admin/orders-manage/pending\">NHẤN VÀO ĐÂY ĐỂ XÁC THỰC ĐƠN HÀNG!.</a>");

        emailSenderService.sendEmail("ongdinh1099@gmail.com", body.toString(),
                "ĐƠN HÀNG MỚI.");
        return orderResponse;
    }

    @PostMapping("post-order-paypal")
    @ResponseBody
    public String postOrderPayPal(@RequestBody Order orderInfo) {
        User user = MyUserDetail.getUserIns();
        if (null == user) return "error";
        orderPayPal = orderByPayPal(orderInfo);
        orderPayPal.setUser(user);
        orderPayPal.setCreatedDate(new Date());
        orderPayPal.setActive(1);
        orderPayPal.setOrderDetails(createdOrderDetail(orderPayPal));
        return "success";
    }

    @GetMapping
    @ResponseBody
    public List getAllOrderByUser(@RequestParam(required = false, defaultValue = "all") String status, @RequestParam(required = false, defaultValue = "0") String id) {
        User user;
        Collection<Order> orderCollection = null;
        if (null == MyUserDetail.getUserIns()) {
            return null;
        } else {
            user = MyUserDetail.getUserIns();
            Collection<Order> collectionOrderUserDB = orderService.getListOrderOfUser(user.getId());
            user.checkAndSetOrderUserDB(collectionOrderUserDB);
            orderCollection = user.getOrders();
        }
        Collection<CustomResponseOrder> listOrderResponse = new HashSet<>();
        for (Order order : orderCollection) {
            CustomResponseOrder orderResponse = CustomResponseOrder.toResponseOrder(order);
            listOrderResponse.add(orderResponse);
        }
        List resp = toList(loadByFilter(listOrderResponse, status, Integer.parseInt(id)));
        return resp;
    }

    public Order orderByCash(Order orderInfo) {
        orderInfo.setOrderStatus("Đang tiếp nhận");
        orderInfo.setPayment("Trực tiếp");
        return orderInfo;
    }

    public Order orderByPayPal(Order orderInfo) {
        orderInfo.setOrderStatus("Đang tiếp nhận");
        orderInfo.setPayment("Online");
        return orderInfo;
    }

    public Collection<OrderDetail> createdOrderDetail(Order order) {
        Collection<OrderDetail> listOrderDetails = new HashSet<>();
        for (CartItemRequest c : CustomResponseCart.listItems) {
            OrderDetail od = new OrderDetail();
            od.setOrder(order);
            od.setProduct(productService.findOneByID(c.getProductID()));
            od.setAmount(c.getAmount());
            od.setActive(c.getActive());
            od.setPrice(c.getPriceProduct());
            od.setInitialPrice(c.getTotalPrice());
            od.updateSalePrice(0);
            od.setTotalPrice(c.getTotalPrice());
            listOrderDetails.add(od);

        }
        return listOrderDetails;
    }

    public boolean insertDBOrderDetail(Order order) {
        for (OrderDetail od : order.getOrderDetails()) {
            od = orderDetailService.insertIntoTable(od);
            if (od == null) return false;
        }
        return true;
    }

    public Collection<CustomResponseOrder> loadByFilter(Collection<CustomResponseOrder> list, String status, int id) {
        Collection<CustomResponseOrder> listResult = new ArrayList<>();
        if (status.equals("all") && id == 0) {
            return list;
        } else if (status.equals("all") && id != 0) {
            for (CustomResponseOrder orderResponse : list) {
                if (orderResponse.getId() == id) {
                    listResult.add(orderResponse);
                    return listResult;
                }
            }
        } else if (!status.equals("all") && id == 0) {
            for (CustomResponseOrder orderResponse : list) {
                if (orderResponse.getStatus().equals(status)) {
                    listResult.add(orderResponse);
                }
            }
        } else if (!status.equals("all") && id != 0) {
            for (CustomResponseOrder orderResponse : list) {
                if (orderResponse.getStatus().equals(status) && orderResponse.getId() == id) {
                    listResult.add(orderResponse);
                }
            }
        }
        return listResult;
    }

    public List toList(Collection<CustomResponseOrder> list) {
        List listResult = new ArrayList<CustomResponseOrder>(list);
        Collections.sort(listResult, Collections.reverseOrder());
        return listResult;
    }

    @PostMapping("deny")
    @ResponseBody
    public String denyOrder(int orderID) {
        System.out.println("DENY ORDER HAS ID ="+orderID);
        User user;
        if (null == MyUserDetail.getUserIns()) {
            return null;
        } else {
            user = MyUserDetail.getUserIns();
            for (Order o : user.getOrders()) {
                if (o.getId() == orderID && o.getOrderStatus().equals("Đang tiếp nhận")) {
                    o.setOrderStatus("Đã hủy");
                    orderService.updateOrderStatus(o);
                    return "Hủy thành công!";
                }
            }
        }
        return "error";
    }
}
