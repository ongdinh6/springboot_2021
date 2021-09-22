package nlu.fit.cellphoneapp.repositories.interfaces;

import nlu.fit.cellphoneapp.entities.CartItem;
import nlu.fit.cellphoneapp.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Repository
public interface ICartRepository extends JpaRepository<CartItem, Integer> {
    List<CartItem> getAllByUser(User user);

    @Modifying
    @Query("delete from CartItem c where c.id = ?1")
    void deleteById(int id);

    @Transactional
    @Modifying
    @Query("delete from CartItem c where c.user.id =?1")
    void deleteAllByUser_Id(int userID);

    CartItem getOneByUserIdAndProductId(int userID, int productID);

}
