package nlu.fit.cellphoneapp.entities;

import lombok.Getter;
import lombok.Setter;
import nlu.fit.cellphoneapp.DTOs.TagAttrDTO;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name="pin")
@Getter
@Setter
public class Pin {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;
    private String capacity;
    private int active;

    //OneToMany Relation product table
    @OneToMany(mappedBy = "pin", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Product> products = new ArrayList<>();

    public Pin updateInfo(TagAttrDTO tagDTO) {
        Pin pin = new Pin();
        pin.id = tagDTO.getId();
        pin.capacity = tagDTO.getCapacity();
        pin.active = tagDTO.getActive();
        return pin;
    }
}
