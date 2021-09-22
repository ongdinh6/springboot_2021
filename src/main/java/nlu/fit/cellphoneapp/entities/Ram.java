package nlu.fit.cellphoneapp.entities;

import lombok.Getter;
import lombok.Setter;
import nlu.fit.cellphoneapp.DTOs.TagAttrDTO;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "ram")
@Setter
@Getter
public class Ram {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;
    private String capacity;
    private int active;

    //OneToMany Relation product table
    @OneToMany(mappedBy = "ram", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Product> products = new ArrayList<>();


    public Ram updateInfo(TagAttrDTO tagDTO) {
        Ram ram = new Ram();
        ram.id = tagDTO.getId();
        ram.capacity = tagDTO.getCapacity();
        ram.active = tagDTO.getActive();
        return ram;
    }
}
