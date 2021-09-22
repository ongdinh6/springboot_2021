package nlu.fit.cellphoneapp.entities;

import lombok.Getter;
import lombok.Setter;
import nlu.fit.cellphoneapp.helper.DateHelper;

import javax.persistence.*;

@Entity
@Table(name = "order_detail")
@Getter
@Setter
public class OrderDetail {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;
    private int amount;
    @Column(name = "initail_price")
    private double initialPrice;
    @Column(name = "saled_price")
    private double saledPrice;
    @Column(name = "total_price")
    private double totalPrice;
    private double price;
    private int active;
    @Column(name = "is_review")
    private int isReviewd;
    @ManyToOne(fetch = FetchType.LAZY)
    private Order order;
    @ManyToOne(fetch = FetchType.EAGER)
    private Product product;


    public void updateSalePrice(double sale) {
        double afterSale = (price * amount) - sale;
        setSaledPrice(afterSale);
    }


    public void updateTotalPrice() {
        setTotalPrice(initialPrice - saledPrice);
    }
}
