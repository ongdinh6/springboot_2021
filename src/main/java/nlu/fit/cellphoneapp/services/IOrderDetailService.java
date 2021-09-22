package nlu.fit.cellphoneapp.services;

import nlu.fit.cellphoneapp.entities.Order;
import nlu.fit.cellphoneapp.entities.OrderDetail;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;

public interface IOrderDetailService {
    OrderDetail insertIntoTable(OrderDetail orderDetail);

    void updateActive(Order o, int active);

    Page<OrderDetail> findAllBySpec(Specification spec, Pageable pageable);

    OrderDetail findOneByActiveId(int id);

    Specification<OrderDetail> getIsNotReviewd(int userId);

    Specification<OrderDetail> getOneById(int orderDetailId);

    boolean save(OrderDetail orderDetail);


}
