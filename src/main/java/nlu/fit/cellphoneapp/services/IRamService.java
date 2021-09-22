package nlu.fit.cellphoneapp.services;
import nlu.fit.cellphoneapp.entities.Ram;
import java.util.List;

public interface IRamService {
    List<Ram> findAllByActive(int active);
    Ram findOneById(int id);
    List<Ram> findAll();
    Ram save(Ram ram);
    Ram updateRam(int id, Ram ram);
}
