package nlu.fit.cellphoneapp.services.impl;

import nlu.fit.cellphoneapp.entities.Brand;
import nlu.fit.cellphoneapp.repositories.interfaces.IBrandRepository;
import nlu.fit.cellphoneapp.services.IBrandService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class BrandServiceImpl implements IBrandService {

    @Autowired
    IBrandRepository brandRepo;

    @Override
    public List<Brand> findAll() {
        return brandRepo.findAll();
    }

    @Override
    public Brand findOneById(int id) {
        return brandRepo.getOne(id);
    }

    @Override
    public List<Brand> findAllByActive(int active) {
        return brandRepo.findAllByActive(active);
    }

    @Override
    public Brand save(Brand brand) {
        return brandRepo.save(brand);
    }


}
