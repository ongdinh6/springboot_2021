package nlu.fit.cellphoneapp.controllers.consumer;

import nlu.fit.cellphoneapp.entities.OrderDetail;
import nlu.fit.cellphoneapp.entities.Review;
import nlu.fit.cellphoneapp.entities.User;
import nlu.fit.cellphoneapp.helper.StringHelper;
import nlu.fit.cellphoneapp.security.MyUserDetail;
import nlu.fit.cellphoneapp.services.IOrderDetailService;
import nlu.fit.cellphoneapp.services.IReviewService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

import java.util.Date;

@Controller
@RequestMapping(value = "/user/review")
public class ReviewController {
    @Autowired
    IReviewService service;
    @Autowired
    IOrderDetailService orderDetailService;
    public static final int ITEM_PER_PENDING_PAGE = 6;
    public static final int ITEM_PER_PAGE = 10;

    @RequestMapping(value = "/pending", method = RequestMethod.GET)
    public ModelAndView pendingReviewPage(@RequestParam(value = "page", required = false, defaultValue = "1") int page) {
        User u = MyUserDetail.getUserIns();
        ModelAndView model = new ModelAndView("/consumer/pending-reviews");
        model.addObject("CONTENT_TITLE", "Nhận Xét Sản Phẩm Đã Mua");
        Specification<OrderDetail> spec = Specification.where(orderDetailService.getIsNotReviewd(u.getId()));
        Pageable pageable = PageRequest.of(page - 1, ITEM_PER_PENDING_PAGE);
        Page<OrderDetail> pages = orderDetailService.findAllBySpec(spec, pageable);
        model.addObject("currentPage", page);
        model.addObject("totalPages", pages.getTotalPages());
        model.addObject("totalRecords", pages.getTotalElements());
        model.addObject("orderDetails", pages.getContent());
        return model;
    }

    @RequestMapping(value = "", method = RequestMethod.GET)
    public ModelAndView reviewPage(@RequestParam(value = "page", required = false, defaultValue = "1") int page) {
        User user = MyUserDetail.getUserIns();
        ModelAndView model = new ModelAndView("/consumer/reviews");
        model.addObject("CONTENT_TITLE", "Nhận Xét Của Tôi");
        Specification<Review> spec = Specification.where(service.getByActiveUser(user.getId()));
        Pageable pageable = PageRequest.of(page - 1, ITEM_PER_PAGE);
        Page<Review> pages = service.findAllBySpec(spec, pageable);
        model.addObject("currentPage", page);
        model.addObject("totalPages", pages.getTotalPages());
        model.addObject("totalRecords", pages.getTotalElements());
        model.addObject("reviews", pages.getContent());
        return model;
    }

    @PostMapping("/create")
    @ResponseBody
    public String create(@RequestParam("orderDetailId") int orderDetailId
            , @RequestParam("content") String content
            , @RequestParam("stars") int stars) {
        User user = MyUserDetail.getUserIns();
        OrderDetail orderDetail;
        if (StringHelper.EmptyOrWhitespace(content)) {
            return "validContent";
        } else if (stars <= 0 || stars > 5) {
            return "validStar";
        } else if ((orderDetail = orderDetailService.findOneByActiveId(orderDetailId)) == null) {
            return "validId";
        } else {
            if (orderDetail.getIsReviewd() == 1) {
                return "validId";
            }
            Review review = new Review();
            review.setUser(user);
            review.setContent(content);
            review.setActive(1);
            review.setProduct(orderDetail.getProduct());
            review.setStars(stars);
            review.setCreatedDate(new Date());
            orderDetail.setIsReviewd(1);
            if (!service.save(review) || !orderDetailService.save(orderDetail)) {
                return "failed";
            }
            return "success";
        }

    }
}

