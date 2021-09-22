package nlu.fit.cellphoneapp.DTOs;

import nlu.fit.cellphoneapp.entities.Order;
import nlu.fit.cellphoneapp.entities.OrderDetail;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.HashSet;

public class CustomResponseOrder implements Comparable<CustomResponseOrder>{
    private int id;
    private String name;
    private String address;
    private String phone;
    private String payment;
    private String status;
    private String createdDate;
    private double totalAll;
    private double saledPrice;
    private double shipPrice;
    private double lastPrice;
    private int amountItems;
    private int active;
    private Collection<CartItemRequest> listOrders;

    public CustomResponseOrder() {
    }

    public CustomResponseOrder(Collection<CartItemRequest> listOrders) {
        this.listOrders = listOrders;
    }

    public int getAmountItems() {
        return amountItems;
    }

    public void setAmountItems(int amountItems) {
        this.amountItems = amountItems;
    }

    public int getActive() {
        return active;
    }

    public void setActive(int active) {
        this.active = active;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }

    public String getPhone() {
        return phone;
    }

    public void setPhone(String phone) {
        this.phone = phone;
    }

    public String getPayment() {
        return payment;
    }

    public void setPayment(String payment) {
        this.payment = payment;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getCreatedDate() {
        return createdDate;
    }

    public void setCreatedDate(String createdDate) {
        this.createdDate = createdDate;
    }

    public double getTotalAll() {
        return totalAll;
    }

    public void setTotalAll(double totalAll) {
        this.totalAll = totalAll;
    }

    public double getSaledPrice() {
        return saledPrice;
    }

    public void setSaledPrice(double saledPrice) {
        this.saledPrice = saledPrice;
    }

    public double getShipPrice() {
        return shipPrice;
    }

    public void setShipPrice(double shipPrice) {
        this.shipPrice = shipPrice;
    }

    public double getLastPrice() {
        return lastPrice;
    }

    public void setLastPrice(double lastPrice) {
        this.lastPrice = lastPrice;
    }

    public Collection<CartItemRequest> getListOrders() {
        return listOrders;
    }

    public void setListOrders(Collection<CartItemRequest> listOrders) {
        this.listOrders = listOrders;
    }

    public boolean equals(CustomResponseOrder obj) {
        if(!obj.address.equals(address)) return false;
        if(!obj.createdDate.equals(createdDate)) return false;
        if(!obj.name.equals(name)) return false;
        if(!obj.payment.equals(payment)) return false;
        if(!obj.phone.equals(phone)) return false;
        if(!obj.status.equals(status)) return false;
        if(obj.shipPrice != shipPrice) return false;
        return true;
    }

    public void updateTotalAll(){
        double all = 0;
        for (CartItemRequest cq: listOrders) {
            all+=cq.getTotalPrice();
        }
        this.totalAll = all;
    }

    public void updateLastPrice(){
        this.lastPrice = totalAll - saledPrice;
    }

    public static CustomResponseOrder toResponseOrder(Order order){
        CustomResponseOrder orderResponse = new CustomResponseOrder();
        Collection<CartItemRequest> listOrderDetail = new HashSet<>();
        orderResponse.setId(order.getId());
        orderResponse.setAddress(order.getAddress());
        orderResponse.setName(order.getNameOfClient());
        orderResponse.setPayment(order.getPayment());
        orderResponse.setPhone(order.getPhoneNumberOfClient());
        orderResponse.setLastPrice(order.getTotalPrice());
        orderResponse.setActive(order.getActive());
        orderResponse.setStatus(order.getOrderStatus());
        DateFormat inputFormatter = new SimpleDateFormat("dd/MM/yyyy");
        orderResponse.setCreatedDate(inputFormatter.format(order.getCreatedDate()));

        for (OrderDetail orderDetail : order.getOrderDetails()) {
            CartItemRequest cq = new CartItemRequest();
            cq.setProductImg(orderDetail.getProduct().getImg().getHost() + orderDetail.getProduct().getImg().getRelativePath());
            cq.setProductName(orderDetail.getProduct().getName());
            cq.setPriceProduct(orderDetail.getProduct().getPrice());
            cq.setAmount(orderDetail.getAmount());
            cq.updateTotalPrice();
            cq.setBrandName(orderDetail.getProduct().getBrand().getName());
            cq.setActive(orderDetail.getActive());
            cq.setProductID(orderDetail.getProduct().getId());
            listOrderDetail.add(cq);
        }
        orderResponse.setListOrders(listOrderDetail);
        orderResponse.updateTotalAll();
        orderResponse.updateLastPrice();
        orderResponse.setAmountItems(listOrderDetail.size());
        return orderResponse;
    }

    @Override
    public int compareTo(CustomResponseOrder o) {
        if(o.id > id) return -1;
        if(o.id < id) return 1;
        return 0;
    }
}
