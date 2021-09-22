package nlu.fit.cellphoneapp.entities;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;

@Entity
@Table(name="item_cart")
@Getter
@Setter
public class CartItem {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private int id;
    @Column(name="total_price")
    private double totalPrice;
    private int amount;
    private int active;
    @ManyToOne
    private User user;
    @ManyToOne
    private Product product;


    @Override
    public String toString() {
        return "Cart{" +
                "id=" + id +
                ", totalPrice=" + totalPrice +
                ", amount=" + amount +
                ", active=" + active +
                ", user=" + user +
                ", product=" + product +
                '}';
    }

    public void updateTotalPrice(){
        setTotalPrice(this.getAmount()*this.getProduct().getPrice());
    }

    public boolean equals(CartItem obj) {
       if(obj.getAmount() != amount) return false;
       if(obj.getProduct().getId() != product.getId()) return false;
       if(obj.getUser().getId() != user.getId()) return false;
       if(obj.getTotalPrice() != totalPrice) return false;
       if(obj.getActive() != active) return false;
       return true;
    }
}
