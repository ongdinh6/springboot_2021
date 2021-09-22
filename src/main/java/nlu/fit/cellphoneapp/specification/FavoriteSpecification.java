package nlu.fit.cellphoneapp.specification;

import nlu.fit.cellphoneapp.entities.*;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Component;

@Component
public class FavoriteSpecification {
    public Specification<Favorite> getFavoriteByUserId(int userId) {
        return (root, query, cb) -> cb.equal(root.get(Favorite_.USER).get(User_.ID), userId);
    }
}
