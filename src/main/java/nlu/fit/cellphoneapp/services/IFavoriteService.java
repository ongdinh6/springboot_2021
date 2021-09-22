package nlu.fit.cellphoneapp.services;

import nlu.fit.cellphoneapp.entities.Favorite;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;

public interface IFavoriteService {
    Favorite save(Favorite newFavorite);

    boolean delete(Favorite favorite);

    Page<Favorite> findBySpec(Specification spec, Pageable pageable);

    Specification<Favorite> getFavoriteByUserId(int userId);

}
