package nlu.fit.cellphoneapp.specification;

import nlu.fit.cellphoneapp.entities.*;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Component;

import javax.persistence.criteria.Predicate;

@Component
public class OrderDetailSpecification {
    public Specification<OrderDetail> getIsNotReview(int userId) {
        return (root, query, cb) -> {
            Predicate ofUser = cb.equal(root.get(OrderDetail_.ORDER).get(Order_.USER).get(User_.ID), userId);
            Predicate successOrder = cb.equal(root.get(OrderDetail_.ORDER).get(Order_.ORDER_STATUS), Order.STATUS.SUCCESS.value());
            Predicate activeOrder = cb.equal(root.get(OrderDetail_.ORDER).get(Order_.ACTIVE), 1);
            Predicate isNotReview = cb.equal(root.get(OrderDetail_.IS_REVIEWD), 0);
            return cb.and(ofUser, successOrder, activeOrder, isNotReview);
        };
    }

    public Specification<OrderDetail> getOneById(int orderDetailId) {
        return (root, query, cb) -> {
            Predicate activeOrder = cb.equal(root.get(OrderDetail_.ORDER).get(Order_.ACTIVE), 1);
            Predicate byId = cb.equal(root.get(OrderDetail_.ID), orderDetailId);
            return cb.and(activeOrder, byId);
        };
    }
}
