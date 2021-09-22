package nlu.fit.cellphoneapp.controllers.consumer;

import nlu.fit.cellphoneapp.entities.Favorite;
import nlu.fit.cellphoneapp.entities.Product;
import nlu.fit.cellphoneapp.entities.User;
import nlu.fit.cellphoneapp.security.MyUserDetail;
import nlu.fit.cellphoneapp.services.IFavoriteService;
import nlu.fit.cellphoneapp.services.IProductService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpSession;

@Controller
@RequestMapping(value = "/user/favorite")
public class FavoriteController {
    @Autowired
    IFavoriteService favoriteService;
    @Autowired
    IProductService productService;
    private static final int ITEM_PER_PAGE = 10;

    @RequestMapping(value = "", method = RequestMethod.GET)
    public ModelAndView favoritePage(@RequestParam(value = "page", required = false, defaultValue = "1") int page) {
        User user = MyUserDetail.getUserIns();
        ModelAndView model = new ModelAndView("/consumer/favorite");
        Specification<Favorite> spec = Specification.where(favoriteService.getFavoriteByUserId(user.getId()));
        Pageable pageable = PageRequest.of(page - 1, ITEM_PER_PAGE);
        Page<Favorite> list = favoriteService.findBySpec(spec, pageable);
        model.addObject("currentPage", page);
        model.addObject("totalPages", list.getTotalPages());
        model.addObject("totalRecords", list.getTotalElements());
        model.addObject("favorites", list.getContent());
        model.addObject("CONTENT_TITLE", "Danh Sách Yêu Thích");
        return model;
    }

    @ResponseBody
    @RequestMapping(value = "/add", method = RequestMethod.POST)
    public String addFavorite(@RequestParam("productId") int productId, HttpSession session) {
        User user = MyUserDetail.getUserIns();
        Product product;
        if (user.hasFavoriteProduct(productId)) {
            return "hasFavoriteProduct";
        } else if ((product = productService.findOneForConsumer(productId)) == null) {
            return "noExist";
        } else {
            Favorite favorite = new Favorite();
            favorite.setUser(user);
            favorite.setProduct(product);
            if ((favorite = favoriteService.save(favorite)) != null) {
                user.addFavorite(favorite);
                return "success";
            } else {
                return "error";
            }
        }
    }

    @ResponseBody
    @RequestMapping(value = "/delete", method = RequestMethod.POST)
    public String removeFavorite(@RequestParam("productId") int productId) {
        User user = MyUserDetail.getUserIns();
        if (!user.hasFavoriteProduct(productId)) {
            return "hasNotFavoriteProduct";
        } else {
            Favorite favorite = user.removeFavorite(productId);
            if (favoriteService.delete(favorite)) {
                return "sucess";
            } else {
                return "error";
            }
        }
    }
}
