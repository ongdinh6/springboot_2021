package nlu.fit.cellphoneapp.DTOs;

import java.util.Collection;
import java.util.HashSet;

public class CustomResponseCart {
    private int amount;
    private double totalAll;
    private double saledPrice;
    private double lastPrice;
    public static Collection<CartItemRequest> listItems;

    public static boolean isEmpty = true;

    public int getAmount() {
        return amount;
    }

    public void setAmount(int amount) {
        this.amount = amount;
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

    public double getLastPrice() {
        return lastPrice;
    }

    public void setLastPrice(double lastPrice) {
        this.lastPrice = lastPrice;
    }

    public Collection<CartItemRequest> getListItems() {
        return listItems;
    }

    public void setListItems(Collection<CartItemRequest> listItems) {
        this.listItems = listItems;
    }

    public void updateTotalAll(){
        double all = 0;
        for (CartItemRequest cq: listItems) {
            all += cq.getTotalPrice();
        }
        this.totalAll = all;
    }
    public void updateLastPrice(){
        this.lastPrice = totalAll - saledPrice;
    }
    public void updateAmount(){
        this.amount = listItems.size();
    }


    public CustomResponseCart(Collection<CartItemRequest> listItems) {
        this.listItems = listItems;
        updateAmount();
        updateTotalAll();
        updateLastPrice();
    }


    public static void clearCart(){
        listItems.clear();
    }


    public static Collection<CartItemRequest> cloneCart(){
        Collection<CartItemRequest> clone = new HashSet<>();
        for (CartItemRequest cq: listItems) {
            clone.add(cq);
        }
        return clone;
    }
}
