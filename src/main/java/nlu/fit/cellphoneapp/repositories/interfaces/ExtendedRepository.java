package nlu.fit.cellphoneapp.repositories.interfaces;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.NoRepositoryBean;

import javax.persistence.TypedQuery;
import java.io.Serializable;
import java.util.List;

@NoRepositoryBean
public interface ExtendedRepository<T, ID extends Serializable>
        extends JpaRepository<T, ID> {
    List<T> findAllBy(Specification<T> specification, Pageable pageable);

    Page<T> readPage(Class<T> entityClass, Pageable pageable, Specification<T> spec);
}
