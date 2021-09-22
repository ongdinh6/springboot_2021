package nlu.fit.cellphoneapp.entities;

import lombok.Getter;
import lombok.Setter;
import nlu.fit.cellphoneapp.DTOs.TagAttrDTO;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name="rom")
@Getter
@Setter
public class Rom {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;
    private String capacity;
    private int active;

    //OneToMany Relation product table
    @OneToMany(mappedBy = "rom", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Product> products = new ArrayList<>();

    public Rom updateInfo(TagAttrDTO tagDTO) {
        Rom rom = new Rom();
        rom.id = tagDTO.getId();
        rom.capacity = tagDTO.getCapacity();
        rom.active = tagDTO.getActive();
        return rom;
    }
}
