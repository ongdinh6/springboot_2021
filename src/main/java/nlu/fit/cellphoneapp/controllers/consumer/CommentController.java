package nlu.fit.cellphoneapp.controllers.consumer;

import nlu.fit.cellphoneapp.entities.Comment;
import nlu.fit.cellphoneapp.entities.Review;
import nlu.fit.cellphoneapp.helper.StringHelper;
import nlu.fit.cellphoneapp.security.MyUserDetail;
import nlu.fit.cellphoneapp.services.ICommentService;
import nlu.fit.cellphoneapp.services.IReviewService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Controller
@RequestMapping(value = "/user/comment")
public class CommentController {
    @Autowired
    ICommentService service;
    @Autowired
    IReviewService reviewService;

    @PostMapping("/create")
    @ResponseBody
    public ResponseEntity create(@RequestParam("content") String content, @RequestParam("reviewId") int reviewId) {
        Review review;
        if (StringHelper.EmptyOrWhitespace(content)) {
            return ResponseEntity.ok("emptyfield");
        } else if ((review = reviewService.findOneBySpec(reviewService.getOneByActiveId(reviewId))) == null) {
            return ResponseEntity.ok("validreview");
        } else {
            Comment newComment = new Comment();
            newComment.setUser(MyUserDetail.getUserIns());
            newComment.setReview(review);
            newComment.setContent(content);
            newComment.setActive(1);
            newComment.setCreatedDate(new Date());
            if (!service.save(newComment)) {
                return ResponseEntity.ok("failed");
            }
            Map<String, String> body = new HashMap<>();
            body.put("name", newComment.getUser().getFullName());
            body.put("content", newComment.getContent());
            body.put("created-date", newComment.toStringCreatedDate());
            return ResponseEntity.ok(body);
        }
    }
}
