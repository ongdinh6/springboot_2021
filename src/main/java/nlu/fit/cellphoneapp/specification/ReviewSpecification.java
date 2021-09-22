package nlu.fit.cellphoneapp.specification;

import nlu.fit.cellphoneapp.entities.*;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Component;

import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Predicate;
import javax.persistence.criteria.Root;

@Component
public class ReviewSpecification {
    public Specification<Review> getByActiveUser(int userId) {
        return (root, query, cb) -> {
            Predicate ofUser = cb.equal(root.get(Review_.USER).get(User_.ID), userId);
            Predicate active = cb.equal(root.get(Review_.ACTIVE), 1);
            return cb.and(ofUser, active);
        };
    }

    public Specification<Review> getByActiveProduct(int productid) {

        return (root, query, cb) -> {
            Predicate ofUser = cb.equal(root.get(Review_.PRODUCT).get(Product_.ID), productid);
            Predicate active = cb.equal(root.get(Review_.ACTIVE), 1);
            return cb.and(ofUser, active);
        };
    }

    public Specification<Review> getOneByActiveId(int reviewId) {
        return (root, query, cb) -> {
            Predicate id = cb.equal(root.get(Review_.ID), reviewId);
            Predicate active = cb.equal(root.get(Review_.ACTIVE), 1);
            return cb.and(id, active);
        };
    }

}
