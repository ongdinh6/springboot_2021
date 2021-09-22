package nlu.fit.cellphoneapp.controllers.consumer;


import nlu.fit.cellphoneapp.DTOs.CartItemRequest;
import nlu.fit.cellphoneapp.DTOs.CustomResponseCart;
import nlu.fit.cellphoneapp.entities.CartItem;
import nlu.fit.cellphoneapp.entities.Product;
import nlu.fit.cellphoneapp.entities.User;
import nlu.fit.cellphoneapp.security.MyUserDetail;
import nlu.fit.cellphoneapp.services.ICartService;
import nlu.fit.cellphoneapp.services.IProductService;
import nlu.fit.cellphoneapp.services.IUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpSession;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;


@Controller
@RequestMapping("/api/cart")
public class CartControllerVer2 {

    @Autowired
    IProductService productService;
    @Autowired
    IUserService userService;
    @Autowired
    ICartService cartService;

    Collection<CartItemRequest> collection = new HashSet<CartItemRequest>();

    @PostMapping
    @ResponseBody
    public CustomResponseCart addToCart(@RequestBody CartItemRequest cartItemRequest) {
        //some action for cart request
        Product infoProduct = productService.findOneByID(cartItemRequest.getProductID());
        cartItemRequest.setPriceProduct(infoProduct.getPrice());
        cartItemRequest.setBrandName(infoProduct.getBrand().getName());
        cartItemRequest.setProductName(infoProduct.getName());
        cartItemRequest.setProductImg(infoProduct.getImg().getHost() + infoProduct.getImg().getRelativePath());
        cartItemRequest.updateTotalPrice();
        //end
        User user;
        //post for cart user
        if (null != (user = MyUserDetail.getUserIns())) {
            cartItemRequest.setUserID(user.getId());
            if (collectionContainProduct(cartItemRequest) == false) collection.add(cartItemRequest);
            if (collection.size() > 0) {
                //need append this collection into user
                setCollectionForUserAfterAppend(user);
            }
            //set collection for response and saved cart item on db
            collection = updateCollectionResponse(user.getCartItems());
            boolean updateOnDB = updateListCartItemOnDB(user.getCartItems());
            if (updateOnDB == false) return null;
        } else {
            //post for cart session
            boolean isEquals = false;
            for (CartItemRequest c : collection) {
                //is has product in cart ==> increments amount this cart item
                if (c.getProductID() == cartItemRequest.getProductID()) {
                    c.setAmount(c.getAmount() + cartItemRequest.getAmount());
                    c.updateTotalPrice();
                    isEquals = true;
                }
            }
            //if has not ==> add new
            if (isEquals == false) {
                collection.add(cartItemRequest);
            }
        }
        CustomResponseCart cartResponse = new CustomResponseCart(collection);
        return cartResponse;
    }

    public boolean collectionContainProduct(CartItemRequest cartItemRequest) {
        CartItem c = cartService.getOneByUserAndProduct(cartItemRequest.getUserID(), cartItemRequest.getProductID());
        if (null == c) {
            return false;
        } else {
            cartItemRequest.setId(c.getId());
            if (collection.size() > 0) {
                for (CartItemRequest cq : collection) {
                    if (cq.getProductID() == cartItemRequest.getProductID()) {
                        cq.setAmount(cartItemRequest.getAmount() + c.getAmount());
                        return true;
                    }
                }
            } else {
                cartItemRequest.setAmount(c.getAmount() + cartItemRequest.getAmount());
                return false;
            }
        }
        return false;
    }

    public boolean updateListCartItemOnDB(Collection<CartItem> cartItems) {
        for (CartItem c : cartItems) {
            c = cartService.insertIntoTable(c);
            if (null == c) return false;
        }
        return true;
    }

    @GetMapping
    @ResponseBody
    public CustomResponseCart getAllCart(HttpSession session) {
        User user;
        Collection<CartItemRequest> cartResponse = collection;
        if (null != MyUserDetail.getUserIns()) {
            user = MyUserDetail.getUserIns();
            if (collection.size() == 0) {
                checkAndSetCartUserDB(user);
                collection = updateCollectionResponse(user.getCartItems());
            } else {
                CustomResponseCart.isEmpty = false;
                setCollectionForUserAfterAppend(user);
                checkAndSetCartUserDB(user);
                collection = updateCollectionResponse(user.getCartItems());
            }
            session.setAttribute(User.SESSION, user);//TEST SESSION
            return new CustomResponseCart(collection);
        } else {
            if (collection.size() > 0) CustomResponseCart.isEmpty = false;
            session.setAttribute("cartSession", new CustomResponseCart(collection));//moi them thu session
            return new CustomResponseCart(collection);
        }
    }

    public void setCollectionForUserAfterAppend(User user) {
        Collection<CartItemRequest> collectionAddNew = user.appendCartSession(collection);
        for (CartItemRequest cartDTO : collectionAddNew) {
            cartDTO.updateTotalPrice();
            CartItem cartItem = cartDTO.toCartItem();
            cartItem.setAmount(cartDTO.getAmount());
            cartItem.setUser(user);
            cartItem.setProduct(productService.findOneByID(cartDTO.getProductID()));
            cartItem.updateTotalPrice();
            user.getCartItems().add(cartItem);
            cartService.insertIntoTable(cartItem);
        }
    }

    public Collection<CartItemRequest> updateCollectionResponse(Collection<CartItem> collection) {
        Collection<CartItemRequest> cartResponse = new HashSet<>();
        for (CartItem c : collection) {
            CartItemRequest cq = new CartItemRequest();
            cq.setId(c.getId());
            cq.setAmount(c.getAmount());
            cq.setTotalPrice(c.getTotalPrice());
            cq.setProductID(c.getProduct().getId());
            cq.setProductName(c.getProduct().getName());
            cq.setProductImg(c.getProduct().getImg().getHost() + c.getProduct().getImg().getRelativePath());
            cq.setUserID(c.getUser().getId());
            cq.setPriceProduct(c.getProduct().getPrice());
            cq.setActive(c.getActive());
            cartResponse.add(cq);
        }
        return cartResponse;
    }

    @PutMapping("{productID}")
    @ResponseBody
    public CustomResponseCart updateAmountCartItem(@PathVariable int productID, @RequestBody int newAmount) {
        for (CartItemRequest cq : collection) {
            if (cq.getProductID() == productID) {
                cq.setAmount(newAmount);
                cq.updateTotalPrice();
                if (cq.getId() != 0) {
                    User user = MyUserDetail.getUserIns();
                    if (null != user) {
                        if (!user.updateCart(cq)) return null;
                        boolean updateAll = updateListCartItemOnDB(user.getCartItems());
                        if (!updateAll) return null;
                    }
                    break;
                }
                break;
            }
        }
        return new CustomResponseCart(collection);
    }

    @DeleteMapping("{productID}")
    @ResponseBody
    public CustomResponseCart deleteCartItem(@PathVariable int productID) {
        for (CartItemRequest cq : collection) {
            if (cq.getProductID() == productID) {
                int idDelete = cq.getId();
                collection.remove(cq);
                if (cq.getId() != 0) {
                    User user = MyUserDetail.getUserIns();
                    if (null != user) {
                        if (!user.removeCartItem(idDelete)) return null;
                        cartService.deleteOne(idDelete);
                    }
                    break;
                }
                break;
            }
        }
        return new CustomResponseCart(collection);
    }

    public Collection<CartItem> checkAndSetCartUserDB(User user) {
        Collection<CartItem> collectionCartUserDB = cartService.getAllByUserID(user.getId());
        Collection<CartItem> listCartDeletedDB = new HashSet<>();
        if (collectionCartUserDB.size() < user.getCartItems().size()) {
            int i = 0;
            while (i < user.getCartItems().size()) {
                boolean isEquals = false;
                CartItem cq = (CartItem) user.getCartItems().toArray()[i];
                for (CartItem c : collectionCartUserDB) {
                    if (cq.getId() == c.getId()) {
                        isEquals = true;
                    }
                }
                i++;
                if (isEquals == false) {
                    listCartDeletedDB.add(cq);
                }
            }
            for (CartItem cartItem : listCartDeletedDB) {
                user.removeCartItem(cartItem.getId());
            }
        }
        int i = 0;
        while (i < collectionCartUserDB.size()) {
            CartItem cart = (CartItem) collectionCartUserDB.toArray()[i];
            for (CartItem c : user.getCartItems()) {
                if (c.getId() == cart.getId()) {
                    if (!c.equals(cart)) {
                        user.updateCartItem(c, cart);
                    }
                }
            }
            i++;
        }
        return user.getCartItems();
    }
}
