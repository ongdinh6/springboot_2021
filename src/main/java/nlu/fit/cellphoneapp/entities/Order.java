package nlu.fit.cellphoneapp.entities;

import lombok.Getter;
import lombok.Setter;
import nlu.fit.cellphoneapp.helper.DateHelper;
import org.hibernate.annotations.LazyCollection;
import org.hibernate.annotations.LazyCollectionOption;

import javax.persistence.*;
import java.util.*;

@Entity
@Table(name = "order")
@Getter
@Setter
public class Order {
    public enum STATUS {
        PENDING("Đang tiếp nhận"), DELIVERING("Đang giao hàng"), SUCCESS("Giao thành công"), CANCELED("Đã hủy");
        private final String value;

        STATUS(String value) {
            this.value = value;
        }

        public String value() {
            return value;
        }
    }

    public enum PAYMENT_TYPE {
        OFFLINE("Trực tiếp"), ONLINE("Online");
        private final String value;

        PAYMENT_TYPE(String value) {
            this.value = value;
        }

        public String value() {
            return value;
        }
    }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;
    @Column(name = "status")
    private String orderStatus;
    @Column(name = "created_date")
    private Date createdDate;
    @Column(name = "address")
    private String address;
    @Column(name = "name")
    private String nameOfClient;
    @Column(name = "phone")
    private String phoneNumberOfClient;
    @Column(name = "total_price")
    private double totalPrice;
    @Column(name = "active")
    private int active;
    @Column(name = "payment")
    private String payment;
    @ManyToOne(fetch = FetchType.LAZY)
    private User user;
    @OneToMany(
            mappedBy = "order",
            cascade = CascadeType.ALL,
            orphanRemoval = true
    )
    private Collection<OrderDetail> orderDetails = new HashSet<>();

    public String toStringCreatedDate() {
        return DateHelper.convertToString(this.createdDate, "dd/MM/yyyy");
    }

    @Override
    public String toString() {
        return "Order{" +
                "id=" + id +
                ", orderStatus='" + orderStatus + '\'' +
                ", createdDate=" + createdDate +
                ", address='" + address + '\'' +
                ", nameOfClient='" + nameOfClient + '\'' +
                ", phoneNumberOfClient='" + phoneNumberOfClient + '\'' +
                ", totalPrice=" + totalPrice +
                ", active=" + active +
                ", user=" + user +
                '}';
    }
}