package nlu.fit.cellphoneapp.repositories.interfaces;
import nlu.fit.cellphoneapp.entities.Rom;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface IRomRepository extends JpaRepository<Rom, Integer> {
    List<Rom> findAllByActive(int active);
}
