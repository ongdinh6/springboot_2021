package nlu.fit.cellphoneapp.services;

import nlu.fit.cellphoneapp.entities.Product;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

public interface IProductService {
    Product findOneByID(int productID);

    Page<Product> getPage(Specification specification, Pageable pageable);

    List<Product> findAll();

    Page<Product> findAll(Specification specification, Pageable pageable);

    Page<Product> findPaginated(int page, int limit);

    List<Product> findAllByActive(int active);

    Product findOneForConsumer(int id);

    List<Product> findAllBy(Specification specification, Pageable pageable);

    Specification<Product> getProductIsActive();

    Specification<Product> getProductsByBrand(int id);

    Specification<Product> getProductsByPin(int id);

    Specification<Product> getProductsByRam(int id);

    Specification<Product> getProductsByRom(int id);

    Specification<Product> getProductByName(String name);

    Product insertIntoTable(Product product);

    boolean deleteOneById(int id);
}
