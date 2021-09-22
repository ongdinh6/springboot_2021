package nlu.fit.cellphoneapp.repositories.interfaces;
import nlu.fit.cellphoneapp.entities.Ram;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;
@Repository
public interface IRamRepository extends JpaRepository<Ram, Integer> {
    List<Ram> findAllByActive(int active);
}
