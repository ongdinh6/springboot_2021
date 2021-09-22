package nlu.fit.cellphoneapp.services.impl;

import nlu.fit.cellphoneapp.entities.Favorite;
import nlu.fit.cellphoneapp.repositories.interfaces.IFavoriteRepository;
import nlu.fit.cellphoneapp.services.IFavoriteService;
import nlu.fit.cellphoneapp.specification.FavoriteSpecification;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class FavoriteServiceImpl implements IFavoriteService {
    @Autowired
    IFavoriteRepository favoriteRepo;
    @Autowired
    FavoriteSpecification favoriteSpecification;

    @Override
    @Transactional(propagation = Propagation.REQUIRED, rollbackFor = Exception.class)
    public Favorite save(Favorite newFavorite) {
        try {
            return favoriteRepo.save(newFavorite);
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    @Transactional(propagation = Propagation.REQUIRED, rollbackFor = Exception.class)
    public boolean delete(Favorite favorite) {
        try {
            favoriteRepo.delete(favorite);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public Page<Favorite> findBySpec(Specification spec, Pageable pageable) {
        return favoriteRepo.findAll(spec, pageable);
    }

    @Override
    public Specification<Favorite> getFavoriteByUserId(int userId) {
        return null;
    }
}
