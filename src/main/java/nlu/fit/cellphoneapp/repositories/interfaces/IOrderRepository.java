package nlu.fit.cellphoneapp.repositories.interfaces;

import nlu.fit.cellphoneapp.entities.Order;
import nlu.fit.cellphoneapp.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.List;

@Repository
public interface IOrderRepository extends JpaRepository<Order, Integer> {
    @Query(value = " select SUM(o.total_price) " +
            "from `order` o " +
            "where o.status=:status and o.payment=:payment and MONTH(o.created_date)=:month and YEAR(o.created_date)=:year "
            , nativeQuery = true)
    Double getProfitByMonth(@Param("status") String status, @Param("month") int month, @Param("year") int year, @Param("payment") String payment);

    @Query(value = " select SUM(o.total_price) " +
            "from `order` o " +
            "where o.created_date > DATE_SUB(CURRENT_DATE, INTERVAL DAYOFMONTH(CURRENT_DATE)-1 DAY) - interval (dayofmonth(curdate()) - 1) day - interval 6 month ", nativeQuery = true)
    Double getProfitHalfYearAgo();


    Collection<Order> getAllByUserId(int userID);


    @Query(value = " select o from Order o where o.orderStatus=:status")
    List<Order> getAllByOrderStatus(@Param("status") String status);

}
