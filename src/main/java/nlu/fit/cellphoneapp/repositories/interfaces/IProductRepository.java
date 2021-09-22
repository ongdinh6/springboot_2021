package nlu.fit.cellphoneapp.repositories.interfaces;

import nlu.fit.cellphoneapp.entities.Product;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface IProductRepository extends JpaRepository<Product, Integer>, JpaSpecificationExecutor<Product>, ExtendedRepository<Product, Integer> {
    List<Product> findAllByActive(int active);


    @Query("select p from Product p " +
            "where p.id=:id and p.active=1 and p.brand.active=1 and p.pin.active=1 and p.rom.active=1 and p.ram.active=1 ")
    Product findOneForConsumer(@Param("id") int id);
}
