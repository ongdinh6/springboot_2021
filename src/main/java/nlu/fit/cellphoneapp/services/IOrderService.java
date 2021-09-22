package nlu.fit.cellphoneapp.services;

import nlu.fit.cellphoneapp.entities.Order;
import org.springframework.data.domain.Page;

import java.util.Collection;
import java.util.Date;
import java.util.List;

public interface IOrderService {
    Order insertIntoTable(Order order);
    Page<Order> findPaginated(int page, int limit);
    Order updatePayment(int orderID, String payment);
    Order getOne(int orderID);
    Order updateOrderStatus (Order order);
    double profitByMonth(Date date,String payment);
    double getProfitHalfYearAgo();
    Collection<Order> getListOrderOfUser(int userID);
    List<Order> listOrderByStatus(String status);


}
