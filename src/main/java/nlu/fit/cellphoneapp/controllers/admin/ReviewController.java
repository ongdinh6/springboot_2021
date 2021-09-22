package nlu.fit.cellphoneapp.controllers.admin;

import nlu.fit.cellphoneapp.entities.Review;
import nlu.fit.cellphoneapp.entities.User;
import nlu.fit.cellphoneapp.security.MyUserDetail;
import nlu.fit.cellphoneapp.services.IReviewService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

@Controller("adminReviewController")
@RequestMapping("/admin/review")
public class ReviewController {
    @Autowired
    IReviewService reviewService;

    @GetMapping
    public ModelAndView getListReviewPage(@RequestParam(value = "page", required = false, defaultValue = "1") int page) {
        ModelAndView model = new ModelAndView("/admin/admin-review-management");
        model.addObject("CONTENT_TITLE", "Quản lý đánh giá");
        Pageable pageable = PageRequest.of(page - 1, 20);
        Page<Review> pages = reviewService.findAllByPage(pageable);
        model.addObject("currentPage", page);
        model.addObject("totalPages", pages.getTotalPages());
        model.addObject("totalRecords", pages.getTotalElements());
        model.addObject("reviews", pages.getContent());
        return model;
    }

    @PutMapping("{id}")
    @ResponseBody
    public String hideDisplayReview(@PathVariable int id){
        Review review = reviewService.getOneById(id);
        if(null == review) return "error";
        if(review.getActive() == 1){
            System.out.println("ẩn đánh giá");
            review.setActive(0);
        }else {
            System.out.println("hiện đánh giá");
            review.setActive(1);
        }
        reviewService.save(review);
        return "success";
    }
}
