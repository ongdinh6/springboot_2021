package nlu.fit.cellphoneapp.DTOs;

import nlu.fit.cellphoneapp.entities.Brand;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.multipart.MultipartFile;
import javax.validation.constraints.NotBlank;

@Validated
public class BrandDTO {
    private int id;
    @NotBlank(message = "Không thể bỏ trống trường này!")
    private String name;
    private MultipartFile logo;
    private int active;

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

    public MultipartFile getLogo() {
        return logo;
    }

    public void setLogo(MultipartFile logo) {
        this.logo = logo;
    }

    public int getActive() {
        return active;
    }

    public void setActive(int active) {
        this.active = active;
    }

    @Override
    public String toString() {
        return "BrandDTO{" +
                "id=" + id +
                ", name='" + name + '\'' +
                ", active=" + active +
                '}';
    }

    public Brand toBrandEntity() {
        Brand brand = new Brand();
        brand.setName(name);
        brand.setActive(active);
        brand.setId(id);
        return brand;
    }
}
