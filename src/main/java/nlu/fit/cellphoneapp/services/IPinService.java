package nlu.fit.cellphoneapp.services;

import nlu.fit.cellphoneapp.entities.Pin;
import nlu.fit.cellphoneapp.entities.Rom;

import java.util.List;

public interface IPinService {
    List<Pin> findAllByActive(int active);

    Pin findOneById(int id);
    List<Pin> findAll();
    Pin save(Pin pin);
    Pin updatePin(int id, Pin pin);
}
