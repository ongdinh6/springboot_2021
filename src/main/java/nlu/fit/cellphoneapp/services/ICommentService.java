package nlu.fit.cellphoneapp.services;

import nlu.fit.cellphoneapp.entities.Comment;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;

import java.util.List;

public interface ICommentService {
    boolean save(Comment comment);

    Page<Comment> findAllBySpec(Specification spec, Pageable pageable);

    List<Comment> findAllBySpec(Specification spec);

    Specification<Comment> getByActiveReviewId(int reviewId);

}
