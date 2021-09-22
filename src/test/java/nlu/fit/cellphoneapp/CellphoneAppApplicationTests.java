package nlu.fit.cellphoneapp;

import nlu.fit.cellphoneapp.entities.Product_;
import nlu.fit.cellphoneapp.entities.Review;
import nlu.fit.cellphoneapp.entities.Review_;
import nlu.fit.cellphoneapp.helper.DateHelper;
import nlu.fit.cellphoneapp.others.BcryptEncoder;
import nlu.fit.cellphoneapp.repositories.custom.ReportRepository;
import nlu.fit.cellphoneapp.repositories.interfaces.IBrandRepository;
import nlu.fit.cellphoneapp.repositories.interfaces.IOrderRepository;
import nlu.fit.cellphoneapp.repositories.interfaces.IReviewRepository;
import nlu.fit.cellphoneapp.repositories.interfaces.IUserRepository;
import nlu.fit.cellphoneapp.services.IOrderService;
import nlu.fit.cellphoneapp.services.IReviewService;
import nlu.fit.cellphoneapp.services.IUserService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;

import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Predicate;
import javax.persistence.criteria.Root;
import java.util.Date;
import java.util.Optional;


@SpringBootTest
class CellphoneAppApplicationTests {
    @Autowired
    IReviewService service;
    @Autowired
    IReviewRepository repo;

    @Test
    void contextLoads() {
        System.out.println(service.findOneBySpec(service.getOneByActiveId(5)) == null);
    }


}




