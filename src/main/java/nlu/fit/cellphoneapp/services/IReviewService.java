package nlu.fit.cellphoneapp.services;

import nlu.fit.cellphoneapp.entities.OrderDetail;
import nlu.fit.cellphoneapp.entities.Review;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;

import java.util.List;

public interface IReviewService {
    boolean save(Review review);

    Page<Review> findAllBySpec(Specification spec, Pageable pageable);

    Page<Review> findAllByPage(Pageable pageable);

    List<Review> findAllBySpec(Specification spec);

    Specification<Review> getByActiveUser(int userId);

    Specification<Review> getByActiveProduct(int productId);

    Specification<Review> getOneByActiveId(int reviewId);

    Review findOneBySpec(Specification spec);

    Review getOneById(int id);

}
