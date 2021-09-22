package nlu.fit.cellphoneapp.controllers.consumer;

import nlu.fit.cellphoneapp.entities.Comment;
import nlu.fit.cellphoneapp.entities.Product;
import nlu.fit.cellphoneapp.entities.Review;
import nlu.fit.cellphoneapp.helper.StringHelper;
import nlu.fit.cellphoneapp.services.ICommentService;
import nlu.fit.cellphoneapp.services.IProductService;
import nlu.fit.cellphoneapp.services.IReviewService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.repository.query.Param;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import java.util.List;

@Controller
@RequestMapping(value = "/product")
public class ProductController {
    @Autowired
    IProductService productService;
    @Autowired
    IReviewService reviewService;
    @Autowired
    ICommentService commentService;
    private static final int ITEM_PER_PAGE = 15;

    @RequestMapping(value = "", method = RequestMethod.GET)
    public ModelAndView listProductPageSearch(
            @RequestParam(value = "page", required = false, defaultValue = "1") int page
            , @RequestParam(value = "brand", required = false, defaultValue = "-1") int brandId
            , @RequestParam(value = "ram", required = false, defaultValue = "-1") int ramId
            , @RequestParam(value = "rom", required = false, defaultValue = "-1") int romId
            , @RequestParam(value = "pin", required = false, defaultValue = "-1") int pinId
            , @RequestParam(value = "sort-type", required = false, defaultValue = "-1") int sortType
            , @RequestParam(value = "sort-order", required = false, defaultValue = "-1") int sortOrder
            , @RequestParam(value = "name", required = false, defaultValue = "") String name) {
        ModelAndView model = new ModelAndView("consumer/product-list");
        Specification<Product> spec = Specification.where(productService.getProductIsActive());
        Pageable pageable = null;
        if (sortOrder > 0 && sortType > 0) {
            Sort sort;
            switch (sortType) {
                case 1:
                    sort = Sort.by("price");
                    break;
                default:
                    sort = Sort.by("id");
                    break;
            }
            switch (sortOrder) {
                case 1:
                    pageable = PageRequest.of(page - 1, ITEM_PER_PAGE, sort.ascending());
                    break;
                case 2:
                    pageable = PageRequest.of(page - 1, ITEM_PER_PAGE, sort.descending());
                    break;
                default:
                    break;
            }
        }
        if (brandId > 0) spec = spec.and(productService.getProductsByBrand(brandId));
        if (ramId > 0) spec = spec.and(productService.getProductsByRam(ramId));
        if (romId > 0) spec = spec.and(productService.getProductsByRom(romId));
        if (pinId > 0) spec = spec.and(productService.getProductsByPin(pinId));
        if (!StringHelper.isNoValue(name)) spec = productService.getProductByName(name);
        if (pageable == null) pageable = PageRequest.of(page - 1, ITEM_PER_PAGE);
        Page<Product> productPage = productService.getPage(spec, pageable);
        model.addObject("currentPage", page);
        model.addObject("totalPages", productPage.getTotalPages());
        model.addObject("totalRecords", productPage.getTotalElements());
        model.addObject("products", productPage.getContent());
        model.addObject("CONTENT_TITLE", "DANH SÁCH SẢN PHẨM");
        return model;
    }

    @RequestMapping(value = "/detail/{id}", method = RequestMethod.GET)
    public ModelAndView productDetailPage(@PathVariable("id") int id) {
        Product product;
        if ((product = productService.findOneForConsumer(id)) != null) {
            ModelAndView model = new ModelAndView("consumer/product-detail");
            List<Review> reviews = reviewService.findAllBySpec(reviewService.getByActiveProduct(product.getId()));
            reviews.forEach(s -> {
                s.setComments(commentService.findAllBySpec(commentService.getByActiveReviewId(s.getId())));
            });
            model.addObject("product", product);
            model.addObject("reviews", reviews);
            model.addObject("CONTENT_TITLE", product.getName());
            return model;
        } else {
            return new ModelAndView("redirect:/");
        }

    }
}
