package nlu.fit.cellphoneapp.services.impl;

import nlu.fit.cellphoneapp.entities.Comment;
import nlu.fit.cellphoneapp.repositories.interfaces.ICommentRepository;
import nlu.fit.cellphoneapp.services.ICommentService;
import nlu.fit.cellphoneapp.specification.CommentSpecification;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class CommentServiceImpl implements ICommentService {
    @Autowired
    ICommentRepository repository;
    @Autowired
    CommentSpecification specification;

    @Override
    @Transactional(propagation = Propagation.REQUIRED, rollbackFor = Exception.class)
    public boolean save(Comment comment) {
        try {
            repository.save(comment);
            return true;
        } catch (Exception e) {
            System.out.println(e.getMessage());
            return false;
        }
    }

    @Override
    public Page<Comment> findAllBySpec(Specification spec, Pageable pageable) {
        return repository.findAll(spec, pageable);
    }

    @Override
    public List<Comment> findAllBySpec(Specification spec) {
        return repository.findAll(spec);
    }

    @Override
    public Specification<Comment> getByActiveReviewId(int reviewId) {
        return specification.getByActiveReviewId(reviewId);
    }
}
