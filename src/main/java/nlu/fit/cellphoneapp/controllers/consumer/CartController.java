package nlu.fit.cellphoneapp.controllers.consumer;

import nlu.fit.cellphoneapp.DTOs.CartItemRequest;
import nlu.fit.cellphoneapp.entities.CartItem;
import nlu.fit.cellphoneapp.entities.Product;
import nlu.fit.cellphoneapp.entities.User;
import nlu.fit.cellphoneapp.services.ICartService;
import nlu.fit.cellphoneapp.services.IProductService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.util.*;

@Controller
public class CartController {
    @Autowired
    ICartService cartService;
    @Autowired
    IProductService productService;
    Set<CartItem> cartItemsSessionV2 = new HashSet<>();
    Set<CartItemRequest> cartSession = new HashSet<>();

    @PostMapping(value = "/add-to-cart", produces = "application/json;charset=UTF-8")
    @ResponseBody
    public Collection<CartItemRequest> addToCart(@RequestBody CartItemRequest cartItem, @RequestHeader(value = "action") String action, HttpSession session, HttpServletResponse resp) {
        resp.setContentType("application/json;charset=UTF-8");

        //create a new cartItem entity from cartItemRequest
        CartItem c = new CartItem();
        c.setId(cartItem.getId());
        Product item = productService.findOneByID(cartItem.getProductID());
        c.setProduct(item);
        c.setAmount(cartItem.getAmount());
        c.setTotalPrice(item.getPrice());
        c.setActive(cartItem.getActive());

        cartSession = (Set<CartItemRequest>) revertToCartItemResponse(updateCart(c, action, session));
        //add this session for user when login (append cart session to list cart user)
        session.setAttribute("cartSession", cartItemsSessionV2);
        return cartSession;
    }

    void print() {
        for (CartItemRequest c : cartSession) {
            System.out.println("product = " + c.getProductID() + ", amount =" + c.getAmount());
        }
    }

    public Collection<CartItem> updateCart(CartItem cartItem, String action, HttpSession session) {
        Collection<CartItem> cartItems = new HashSet<>();
        if (true == User.checkUserSession(session)) {
            User user = (User) session.getAttribute(User.SESSION);
            cartItems = user.getCartItems();
        } else {
            cartItems = cartItemsSessionV2;
        }
        if (action.equals("add")) {
            //click add at product list page again, amount++
            for (CartItem c : cartItems) {
                if (c.getProduct().getId() == cartItem.getProduct().getId()) {
                    c.setAmount(c.getAmount() + 1);
                    c.updateTotalPrice();
                    //cart user update inside db
                    if (User.checkUserSession(session) == true) {
                        User user = (User) session.getAttribute(User.SESSION);
                        cartItem = cartService.getOneByUserAndProduct(user.getId(), cartItem.getProduct().getId());
                        cartItem.setAmount(c.getAmount());
                        cartItem.setTotalPrice(c.getTotalPrice());
                        cartItem.setUser((User) session.getAttribute(User.SESSION));
                        cartService.insertIntoTable(cartItem);
                    }
                    return cartItems;
                }
            }
            cartItems.add(cartItem);
            if (User.checkUserSession(session) == true) {
                cartItem.setUser((User) session.getAttribute(User.SESSION));
                cartService.insertIntoTable(cartItem);
            }
        } else if (action.equals("update")) {
            for (CartItem c : cartItems) {
                if (c.getProduct().getId() == cartItem.getProduct().getId()) {
                    c.setAmount(cartItem.getAmount());
                    c.updateTotalPrice();
                    if (User.checkUserSession(session) == true) cartService.insertIntoTable(c);
                    break;
                }
            }
        }
        return cartItems;
    }

    @DeleteMapping("/cart/delete")
    @ResponseBody
    public String ajaxDeleteCartItem(@RequestParam int productID, HttpSession session) {
        Collection<CartItemRequest> listCart = deleteCart(productID, session);
        if (listCart.size() == 0) return "/cart"; //load again with empty cart
        return "success";
    }

    public Collection<CartItemRequest> deleteCart(int productID, HttpSession session) {
        if (User.checkUserSession(session) == true) {
            //remove on cart user
            User user = (User) session.getAttribute(User.SESSION);
            for (CartItem c : user.getCartItems()) {
                if (c.getProduct().getId() == productID) {
                    user.getCartItems().remove(c);
                    cartService.deleteOne(c.getId());
                    deleteOneCartSessionV2(productID);
                    break;
                } else {
                    return null;
                }
            }
            return revertToCartItemResponse(user.getCartItems());
        } else {
            //remove on cart session
            for (CartItemRequest c : cartSession) {
                if (c.getProductID() == productID) {
                    cartSession.remove(c);
                    deleteOneCartSessionV2(productID);
                    break;
                }
            }
            print();
            return revertToCartItemResponse(cartItemsSessionV2);
        }

    }

    //delete on session
    public boolean deleteOneCartSessionV2(int productID) {
        for (CartItem c : cartItemsSessionV2) {
            if (c.getProduct().getId() == productID) {
                cartItemsSessionV2.remove(c);
                return true;
            }
        }
        return false;
    }

    //check user session
    public boolean checkUserSession(HttpSession session) {
        if (null == session.getAttribute(User.SESSION)) return false;
        return true;
    }

    public Collection<CartItemRequest> getCart(HttpSession session) {
        if (null != session.getAttribute("cartSession")) {
            return (Collection<CartItemRequest>) session.getAttribute("cartSession");
        } else {
            return revertToCartItemResponse(((User) session.getAttribute(User.SESSION)).getCartItems());
        }
    }

    @GetMapping("/cart/all")
    @ResponseBody
    public Collection<CartItemRequest> loadCart(HttpSession session, HttpServletResponse resp) {
        resp.setContentType("application/json;charset=UTF-8");
        if (User.checkUserSession(session) == true) {
            User user = (User) session.getAttribute(User.SESSION);
            cartSession.clear();
            cartSession = new HashSet<>();
            cartItemsSessionV2.clear();
            return revertToCartItemResponse(user.getCartItems());
        } else {
            return cartSession;
        }
    }

    public Collection<CartItemRequest> revertToCartItemResponse(Collection<CartItem> cartItems) {
        Collection<CartItemRequest> cartItemResponse = new HashSet<>();
        for (CartItem i : cartItems) {
            CartItemRequest ci = new CartItemRequest();
            ci.setActive(i.getActive());
            ci.setAmount(i.getAmount());
            ci.setProductID(i.getProduct().getId());
            ci.setProductImg(i.getProduct().getImg().getHost() + i.getProduct().getImg().getRelativePath());
            ci.setProductName(i.getProduct().getName());
            ci.updateTotalPrice();
            cartItemResponse.add(ci);
        }
        return cartItemResponse;
    }

    @GetMapping("/cart")
    public ModelAndView getViewCart(HttpSession session) {
        ModelAndView mv = new ModelAndView("consumer/cart");
        User user = (User) session.getAttribute(User.SESSION);
//        if (User.checkUserSession(session) == true && user.getCartItems().size() == 0) {
//            //th co user nhung cart dang empty
//            mv.setViewName("/consumer/cart-empty");
//        } else if (User.checkUserSession(session) == false && cartSession.size() == 0) {
//            //th chua co user va cart session dang empty
//            mv.setViewName("/consumer/cart-empty");
//        } else {
//            //da hoac chua co va cartSession size > 0
//            mv.addObject("cartSession", cartSession);
//        }
        return mv;
    }

    @GetMapping("/checkout1")
    public ModelAndView goToCheckoutPage(HttpSession session) {
        ModelAndView mv = new ModelAndView();
        User user = (User) session.getAttribute(User.SESSION);
        Collection<CartItem> cs = (Set<CartItem>) session.getAttribute("cartSession");

        if (User.checkUserSession(session) == true) {
            if (user.getActive() != 1) {
                mv.setViewName("consumer/active-account");
                mv.addObject("cartSession", cartSession);
                return mv;
            }
            if (user.getCartItems().size() == 0) {
                mv.setViewName("consumer/cart-empty");
                mv.addObject("cartSession", cartSession);
                return mv;
            } else {
                mv.setViewName("consumer/checkout");
                mv.addObject("cartSession", cartSession);
                return mv;
            }
        } else {
            return redirectWithCartSession(cs);
        }
    }

    public ModelAndView redirectWithCartSession(Collection<CartItem> cs) {
        ModelAndView mv = new ModelAndView();
        if (null != cs && cs.size() > 0) {
            mv.setViewName("consumer/checkout");
            mv.addObject("cartSession", cartSession);
            return mv;
        } else {
            mv.setViewName("consumer/cart-empty");
            mv.addObject("cartSession", cartSession);
            return mv;
        }
    }

}
