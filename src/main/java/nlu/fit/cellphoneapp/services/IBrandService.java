package nlu.fit.cellphoneapp.services;

import nlu.fit.cellphoneapp.entities.Brand;

import java.util.List;

public interface IBrandService {
    List<Brand> findAll();
    Brand findOneById(int id);
    List<Brand> findAllByActive(int active);
    Brand save(Brand brand);

}
