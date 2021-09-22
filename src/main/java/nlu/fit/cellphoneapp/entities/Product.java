package nlu.fit.cellphoneapp.entities;


import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import nlu.fit.cellphoneapp.converters.ImageAddress;
import nlu.fit.cellphoneapp.converters.ImageAddressConventer;
import nlu.fit.cellphoneapp.others.Link;
import org.hibernate.annotations.LazyCollection;
import org.hibernate.annotations.LazyCollectionOption;
import org.springframework.context.annotation.Lazy;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Entity
@Table(name = "product")
@Getter
@Setter
public class Product {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;
    @Convert(converter = ImageAddressConventer.class)
    private ImageAddress img;
    private String name;
    private double price;
    private int amount;
    private int warranty;
    @Convert(converter = ImageAddressConventer.class)
    private ImageAddress img01;
    @Convert(converter = ImageAddressConventer.class)
    private ImageAddress img02;
    @Convert(converter = ImageAddressConventer.class)
    private ImageAddress img03;
    @Convert(converter = ImageAddressConventer.class)
    private ImageAddress img04;
    private String size;
    @Column(name = "selfie_camera")
    private String selfieCamera;
    @Column(name = "main_camera")
    private String mainCamera;
    private int active;
    //add new long description
    @Column(name = "long_description")
    private String longDescription;

    //relationship to other table
    @ManyToOne(fetch = FetchType.LAZY)
    private Ram ram;
    @ManyToOne(fetch = FetchType.LAZY)
    private Rom rom;
    @ManyToOne(fetch = FetchType.LAZY)
    private Pin pin;
    @ManyToOne(fetch = FetchType.LAZY)
    private Brand brand;

    @JsonIgnore
    @OneToMany(
            mappedBy = "product",
            cascade = CascadeType.ALL,
            orphanRemoval = true,
            fetch = FetchType.LAZY
    )
    private Set<CartItem> cartItems = new HashSet<>();
    @OneToMany(
            mappedBy = "product",
            cascade = CascadeType.ALL,
            orphanRemoval = true
    )
    @LazyCollection(LazyCollectionOption.FALSE)
    private Set<OrderDetail> orderDetails = new HashSet<>();

    @OneToMany(fetch = FetchType.LAZY, mappedBy = "product")
    private Set<Favorite> favorites;
    @OneToMany(fetch = FetchType.LAZY, mappedBy = "product")
    private Set<Review> reviews;

}
