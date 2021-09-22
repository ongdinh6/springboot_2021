package nlu.fit.cellphoneapp.services.impl;

import nlu.fit.cellphoneapp.entities.Ram;
import nlu.fit.cellphoneapp.repositories.interfaces.IRamRepository;
import nlu.fit.cellphoneapp.services.IRamService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class RamServiceImpl implements IRamService {
    @Autowired
    IRamRepository ramRepo;
    @Override
    public List<Ram> findAllByActive(int active) {
        return ramRepo.findAllByActive(active);
    }

    @Override
    public Ram findOneById(int id) {
        return ramRepo.getOne(id);
    }

    @Override
    public List<Ram> findAll() {
        return ramRepo.findAll();
    }

    @Override
    public Ram save(Ram ram) {
        return ramRepo.save(ram);
    }

    @Override
    public Ram updateRam(int id, Ram ram) {
        Ram current = ramRepo.getOne(id);
        current.setActive(ram.getActive());
        current.setCapacity(ram.getCapacity());
        return ramRepo.save(current);
    }
}
