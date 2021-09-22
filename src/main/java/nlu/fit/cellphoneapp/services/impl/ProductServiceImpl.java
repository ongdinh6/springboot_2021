package nlu.fit.cellphoneapp.services.impl;

import nlu.fit.cellphoneapp.entities.Product;
import nlu.fit.cellphoneapp.repositories.interfaces.IProductRepository;
import nlu.fit.cellphoneapp.services.IProductService;
import nlu.fit.cellphoneapp.specification.ProductSpecification;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ProductServiceImpl implements IProductService {

    @Autowired
    IProductRepository productRepo;
    @Autowired
    ProductSpecification productSpec;

    @Override
    public Product findOneByID(int productID) {
        return productRepo.getOne(productID);
    }

    @Override
    public Page<Product> getPage(Specification specification, Pageable pageable) {
        return productRepo.readPage(Product.class, pageable, specification);
    }

    @Override
    public List<Product> findAll() {
        return productRepo.findAll();
    }

    @Override
    public Page<Product> findAll(Specification specification, Pageable pageable) {
        return productRepo.findAll(specification, pageable);
    }

    @Override
    public Page<Product> findPaginated(int page, int limit) {
        Pageable pageable = PageRequest.of(page - 1, limit);
        return productRepo.findAll(pageable);
    }

    @Override
    public List<Product> findAllByActive(int active) {
        return productRepo.findAllByActive(active);
    }

    @Override
    public Product findOneForConsumer(int id) {
        return productRepo.findOneForConsumer(id);
    }

    @Override
    public List<Product> findAllBy(Specification specification, Pageable pageable) {
        return productRepo.findAllBy(specification, pageable);
    }

    @Override
    public Specification<Product> getProductIsActive() {
        return productSpec.getProductIsActive();
    }

    @Override
    public Specification<Product> getProductsByBrand(int id) {
        return productSpec.getProductsByBrand(id);
    }

    @Override
    public Specification<Product> getProductsByPin(int id) {
        return productSpec.getProductsByPin(id);
    }

    @Override
    public Specification<Product> getProductsByRam(int id) {
        return productSpec.getProductsByRam(id);
    }

    @Override
    public Specification<Product> getProductsByRom(int id) {
        return productSpec.getProductsByRom(id);
    }

    @Override
    public Specification<Product> getProductByName(String name) {
        return productSpec.getProductByName(name);
    }

    @Override
    public Product insertIntoTable(Product product) {
        return productRepo.save(product);
    }

    @Override
    public boolean deleteOneById(int id) {
        productRepo.deleteById(id);
        return true;
    }


}
