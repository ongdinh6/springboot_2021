package nlu.fit.cellphoneapp.services.impl;

import nlu.fit.cellphoneapp.entities.Order;
import nlu.fit.cellphoneapp.entities.OrderDetail;
import nlu.fit.cellphoneapp.repositories.interfaces.IOrderDetailRepository;
import nlu.fit.cellphoneapp.services.IOrderDetailService;
import nlu.fit.cellphoneapp.specification.OrderDetailSpecification;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Service
public class OrderDetailServiceImpl implements IOrderDetailService {
    @Autowired
    IOrderDetailRepository orderDetailRepo;
    @Autowired
    OrderDetailSpecification spec;

    @Override
    public OrderDetail insertIntoTable(OrderDetail orderDetail) {
        return orderDetailRepo.save(orderDetail);
    }

    @Override
    public void updateActive(Order o, int active) {
        List<OrderDetail> listOrderDetail = orderDetailRepo.getAllByOrder(o);
        for (OrderDetail od : listOrderDetail) {
            od.setActive(1);
            orderDetailRepo.save(od);
        }
    }

    @Override
    public Page<OrderDetail> findAllBySpec(Specification spec, Pageable pageable) {
        return orderDetailRepo.findAll(spec, pageable);
    }

    @Override
    public OrderDetail findOneByActiveId(int id) {
        return orderDetailRepo.findOneByActiveId(id);
    }


    @Override
    public Specification<OrderDetail> getIsNotReviewd(int userId) {
        return spec.getIsNotReview(userId);
    }

    @Override
    public Specification<OrderDetail> getOneById(int orderDetailId) {
        return spec.getOneById(orderDetailId);
    }

    @Override
    @Transactional(propagation = Propagation.REQUIRED, rollbackFor = Exception.class)
    public boolean save(OrderDetail orderDetail) {
        try {
            orderDetailRepo.save(orderDetail);
            return true;
        } catch (Exception e) {
            return false;
        }
    }


}
