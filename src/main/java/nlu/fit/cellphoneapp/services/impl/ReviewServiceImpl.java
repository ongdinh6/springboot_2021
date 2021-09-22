package nlu.fit.cellphoneapp.services.impl;

import nlu.fit.cellphoneapp.entities.OrderDetail;
import nlu.fit.cellphoneapp.entities.Review;
import nlu.fit.cellphoneapp.repositories.interfaces.IReviewRepository;
import nlu.fit.cellphoneapp.services.IReviewService;
import nlu.fit.cellphoneapp.specification.ReviewSpecification;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class ReviewServiceImpl implements IReviewService {
    @Autowired
    IReviewRepository repo;
    @Autowired
    ReviewSpecification spec;

    @Override
    @Transactional(propagation = Propagation.REQUIRED, rollbackFor = Exception.class)
    public boolean save(Review review) {
        try {
            repo.save(review);
            return true;
        } catch (Exception e) {
            System.out.println(e.getMessage());
            return false;
        }
    }

    @Override
    public Page<Review> findAllBySpec(Specification spec, Pageable pageable) {
        return repo.findAll(spec, pageable);
    }

    @Override
    public List<Review> findAllBySpec(Specification spec) {
        return repo.findAll(spec);
    }

    @Override
    public Specification<Review> getByActiveUser(int userId) {
        return spec.getByActiveUser(userId);
    }

    @Override
    public Specification<Review> getByActiveProduct(int productId) {
        return spec.getByActiveProduct(productId);
    }

    @Override
    public Specification<Review> getOneByActiveId(int reviewId) {
        return spec.getOneByActiveId(reviewId);
    }

    @Override
    public Review findOneBySpec(Specification spec) {
        return (Review) repo.findOne(spec).orElse(null);
    }

    @Override
    public Page<Review> findAllByPage(Pageable pageable) {
        return repo.findAll(pageable);
    }

    @Override
    public Review getOneById(int id) {
        return repo.findById(id).get();
    }
}
