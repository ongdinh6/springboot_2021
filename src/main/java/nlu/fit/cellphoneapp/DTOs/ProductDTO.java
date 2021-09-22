package nlu.fit.cellphoneapp.DTOs;

import nlu.fit.cellphoneapp.converters.ImageAddressConventer;
import nlu.fit.cellphoneapp.entities.Product;
import org.springframework.web.multipart.MultipartFile;

public class ProductDTO {
    private String id;
    private String name;
    private double price;
    private MultipartFile img;
    private MultipartFile img01;
    private MultipartFile img02;
    private MultipartFile img03;
    private MultipartFile img04;
    private int brandID;
    private int ramID;
    private int romID;
    private int pinID;
    private String size;
    private String selfieCamera;
    private String mainCamera;
    private String longDescription;
    private int active;

    public MultipartFile getImg01() {
        return img01;
    }

    public void setImg01(MultipartFile img01) {
        this.img01 = img01;
    }

    public MultipartFile getImg02() {
        return img02;
    }

    public void setImg02(MultipartFile img02) {
        this.img02 = img02;
    }

    public MultipartFile getImg03() {
        return img03;
    }

    public void setImg03(MultipartFile img03) {
        this.img03 = img03;
    }

    public MultipartFile getImg04() {
        return img04;
    }

    public void setImg04(MultipartFile img04) {
        this.img04 = img04;
    }

    public MultipartFile getImg() {
        return img;
    }

    public void setImg(MultipartFile img) {
        this.img = img;
    }

    public int getActive() {
        return active;
    }

    public void setActive(int active) {
        this.active = active;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public double getPrice() {
        return price;
    }

    public void setPrice(double price) {
        this.price = price;
    }

    public int getBrandID() {
        return brandID;
    }

    public void setBrandID(int brandID) {
        this.brandID = brandID;
    }

    public int getRamID() {
        return ramID;
    }

    public void setRamID(int ramID) {
        this.ramID = ramID;
    }

    public int getRomID() {
        return romID;
    }

    public void setRomID(int romID) {
        this.romID = romID;
    }

    public int getPinID() {
        return pinID;
    }

    public void setPinID(int pinID) {
        this.pinID = pinID;
    }

    public String getSize() {
        return size;
    }

    public void setSize(String size) {
        this.size = size;
    }

    public String getSelfieCamera() {
        return selfieCamera;
    }

    public void setSelfieCamera(String selfieCamera) {
        this.selfieCamera = selfieCamera;
    }

    public String getMainCamera() {
        return mainCamera;
    }

    public void setMainCamera(String mainCamera) {
        this.mainCamera = mainCamera;
    }

    public String getLongDescription() {
        return longDescription;
    }

    public void setLongDescription(String longDescription) {
        this.longDescription = longDescription;
    }

    public Product toProductEntity() {
        Product product = new Product();
        product.setName(this.name);
        product.setActive(active);
        product.setLongDescription(longDescription);
        product.setSelfieCamera(selfieCamera);
        product.setMainCamera(mainCamera);
        product.setSize(size);
        product.setPrice(price);
        product.setWarranty(12);
        product.setAmount(30);

        return product;
    }
}
