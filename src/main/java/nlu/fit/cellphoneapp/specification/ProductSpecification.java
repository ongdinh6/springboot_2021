package nlu.fit.cellphoneapp.specification;

import nlu.fit.cellphoneapp.entities.*;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Component;

import javax.persistence.criteria.Predicate;

@Component
public final class ProductSpecification {
    public Specification<Product> getProductIsActive() {
        return (root, query, cb) -> {
            Predicate activeBrand = cb.equal(root.get(Product_.BRAND).get(Brand_.ACTIVE), 1);
            Predicate activePin = cb.equal(root.get(Product_.PIN).get(Pin_.ACTIVE), 1);
            Predicate activeRam = cb.equal(root.get(Product_.RAM).get(Ram_.ACTIVE), 1);
            Predicate activeRom = cb.equal(root.get(Product_.ROM).get(Rom_.ACTIVE), 1);
            return cb.and(activeBrand, activePin, activeRam, activeRom);
        };
    }

    public Specification<Product> getProductsByBrand(int id) {
        return (root, query, cb) -> cb.equal(root.get(Product_.BRAND).get(Brand_.ID), id);
    }

    public Specification<Product> getProductsByPin(int id) {
        return (root, query, cb) -> cb.equal(root.get(Product_.PIN).get(Pin_.ID), id);
    }

    public Specification<Product> getProductsByRam(int id) {
        return (root, query, cb) -> cb.equal(root.get(Product_.RAM).get(Ram_.ID), id);

    }

    public Specification<Product> getProductsByRom(int id) {
        return (root, query, cb) -> cb.equal(root.get(Product_.ROM).get(Rom_.ID), id);
    }

    public Specification<Product> getProductByName(String name) {
        return (root, query, cb) -> cb.like(root.get(Product_.name), "%" + name + "%");
    }
}
