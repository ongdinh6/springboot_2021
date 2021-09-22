package nlu.fit.cellphoneapp.DTOs;

import nlu.fit.cellphoneapp.entities.CartItem;

public class CartItemRequest {
    private int id;
    private int userID;
    private int productID;
    private int amount;
    private String productName;
    private String productImg;
    private double totalPrice;
    private double priceProduct;
    private int active;
    private String brandName;
    public CartItemRequest() {
    }


    public CartItemRequest(int id, int userID, int productID, int amount, String productName, String productImg, double totalPrice, int active) {
        this.id = id;
        this.userID = userID;
        this.productID = productID;
        this.amount = amount;
        this.productName = productName;
        this.productImg = productImg;
        this.totalPrice = totalPrice;
        this.active = active;
    }

    public String getBrandName() {
        return brandName;
    }

    public void setBrandName(String brandName) {
        this.brandName = brandName;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public int getUserID() {
        return userID;
    }

    public void setUserID(int userID) {
        this.userID = userID;
    }

    public int getProductID() {
        return productID;
    }

    public void setProductID(int productID) {
        this.productID = productID;
    }

    public int getAmount() {
        return amount;
    }

    public void setAmount(int amount) {
        this.amount = amount;
    }

    public String getProductName() {
        return productName;
    }

    public void setProductName(String productName) {
        this.productName = productName;
    }

    public String getProductImg() {
        return productImg;
    }

    public void setProductImg(String productImg) {
        this.productImg = productImg;
    }

    public double getTotalPrice() {
        return totalPrice;
    }

    public void setTotalPrice(double totalPrice) {
        this.totalPrice = totalPrice;
    }

    public int getActive() {
        return active;
    }

    public void setActive(int active) {
        this.active = active;
    }

    public double getPriceProduct() {
        return priceProduct;
    }

    public void setPriceProduct(double priceProduct) {
        this.priceProduct = priceProduct;
    }

    @Override
    public String toString() {
        return "CartItemRequest{" +
                "id=" + id +
                ", userID=" + userID +
                ", productID=" + productID +
                ", amount=" + amount +
                ", productName='" + productName + '\'' +
                ", productImg='" + productImg + '\'' +
                ", totalPrice=" + totalPrice +
                ", active=" + active +
                '}';
    }


    public void updateTotalPrice(double currentPrice){
        setTotalPrice(this.amount*currentPrice);
    }

    public void updateTotalPrice(){
        setTotalPrice(this.amount*priceProduct);
    }

    public CartItem toCartItem(){
        CartItem cartItem = new CartItem();
        cartItem.setActive(1);
        return cartItem;
    }

}
