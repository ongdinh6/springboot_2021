package nlu.fit.cellphoneapp.repositories;

import nlu.fit.cellphoneapp.entities.Product;
import nlu.fit.cellphoneapp.repositories.interfaces.ExtendedRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.data.jpa.repository.support.JpaEntityInformation;
import org.springframework.data.jpa.repository.support.SimpleJpaRepository;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.TypedQuery;
import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Root;
import java.io.Serializable;
import java.util.List;

public class ExtendedRepositoryImpl<T, ID extends Serializable>
        extends SimpleJpaRepository<T, ID> implements ExtendedRepository<T, ID> {
    @PersistenceContext
    EntityManager em;

    public ExtendedRepositoryImpl(JpaEntityInformation<T, ?> entityInformation, EntityManager em) {
        super(entityInformation, em);
        this.em = em;
    }

    public ExtendedRepositoryImpl(Class<T> domainClass, EntityManager em) {
        super(domainClass, em);
        this.em = em;
    }

    public List<T> findAllBy(Specification<T> aSpecification, Pageable aPageable) {
        TypedQuery<T> query = getQuery(aSpecification, aPageable);
        query.setFirstResult((int) aPageable.getOffset());
        query.setMaxResults(aPageable.getPageSize());
        return query.getResultList();
    }

    public Page<T> readPage(Class<T> entityClass, Pageable pageable, Specification<T> spec) {
        TypedQuery<T> query = getQuery(spec, pageable);
        query.setFirstResult(pageable.getPageNumber() * pageable.getPageSize());
        query.setMaxResults(pageable.getPageSize());
        List<T> content = query.getResultList();
        return new PageImpl<T>(content, pageable, getEntityCount(entityClass, spec));
    }

    private long getEntityCount(Class<T> entityClass, Specification<T> spec) {
        CriteriaBuilder cb = em.getCriteriaBuilder();
        CriteriaQuery<Long> count = cb.createQuery(Long.class);
        CriteriaQuery<T> criteriaQuery = cb.createQuery(entityClass);
        Root<T> root = count.from(entityClass);
        count.select(cb.count(root)).where(spec.toPredicate(root, criteriaQuery, cb));
        return em.createQuery(count).getSingleResult();
    }
}
