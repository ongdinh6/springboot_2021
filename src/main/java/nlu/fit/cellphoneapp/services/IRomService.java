package nlu.fit.cellphoneapp.services;

import nlu.fit.cellphoneapp.entities.Rom;

import java.util.List;

public interface IRomService {
    List<Rom> findAllByActive(int active);
    Rom findOneById(int id);
    List<Rom> findAll();
    Rom save (Rom rom);
    Rom updateRom(int id, Rom rom);
}
