package nlu.fit.cellphoneapp.services.impl;

import nlu.fit.cellphoneapp.entities.CartItem;
import nlu.fit.cellphoneapp.entities.User;
import nlu.fit.cellphoneapp.repositories.interfaces.ICartRepository;
import nlu.fit.cellphoneapp.repositories.interfaces.IProductRepository;
import nlu.fit.cellphoneapp.repositories.interfaces.IUserRepository;
import nlu.fit.cellphoneapp.services.ICartService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class CartServiceImpl implements ICartService {

    @Autowired
    ICartRepository cartRepo;
    @Autowired
    IProductRepository productRepo;
    @Autowired
    IUserRepository userRepo;

    @Override
    public boolean isInCart(int productID, int amount, int userID) {
        List<CartItem> items = cartRepo.getAllByUser(userRepo.getOne(userID));
        for (CartItem item : items) {
            if (item.getProduct().getId() == productID) return true;
        }
        return false;
    }

    @Override
    public CartItem insertIntoTable(CartItem cartItem) {
        CartItem cartItemEntity = cartItem;
        if (cartItem.getId() == 0) {
            cartItemEntity = cartRepo.save(cartItemEntity);
        } else {
            if (cartItem.getProduct().getId() != 0) {
                CartItem oldCartItem = cartRepo.getOne(cartItem.getId());
                oldCartItem.setAmount(cartItem.getAmount());
                oldCartItem.setTotalPrice(cartItem.getTotalPrice());
                cartItemEntity = cartRepo.save(cartItemEntity);
            }
        }
        return cartItemEntity;
    }

    @Override
    public List<CartItem> getAllByUserID(int userID) {
        List<CartItem> cartItemList = cartRepo.getAllByUser(userRepo.getOne(userID));
        return cartItemList;
    }

    @Override
    public CartItem getOneCartItem(int id) {
        return cartRepo.getOne(id);
    }

    @Override
    public void deleteOne(int id) {
        cartRepo.deleteById(id);
    }

    @Override
    public boolean removeAllByUserId(int userID) {
        cartRepo.deleteAllByUser_Id(userID);
        return (getAllByUserID(userID).size() == 0 ? true : false);
    }

    @Override
    public CartItem getOneByUserAndProduct(int userID, int productID) {
        return cartRepo.getOneByUserIdAndProductId(userID, productID);
    }

}
