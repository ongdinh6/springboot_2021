package nlu.fit.cellphoneapp.specification;

import nlu.fit.cellphoneapp.entities.Comment;
import nlu.fit.cellphoneapp.entities.Comment_;
import nlu.fit.cellphoneapp.entities.Review_;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Component;

import javax.persistence.criteria.Predicate;

@Component
public class CommentSpecification {
    public Specification<Comment> getByActiveReviewId(int reviewId) {
        return (root, query, cb) -> {
            Predicate ofUser = cb.equal(root.get(Comment_.REVIEW).get(Review_.ID), reviewId);
            Predicate active = cb.equal(root.get(Comment_.ACTIVE), 1);
            return cb.and(ofUser, active);
        };
    }
}
