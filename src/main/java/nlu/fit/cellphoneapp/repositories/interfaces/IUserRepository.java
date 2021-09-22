package nlu.fit.cellphoneapp.repositories.interfaces;

import nlu.fit.cellphoneapp.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
public interface IUserRepository extends JpaRepository<User, Integer> {
    User findOneByEmail(String email);

    @Transactional
    User save(User user);

    @Query("select u from User u where u.email=:email and u.active=:active")
    User findOneByEmailActive(@Param("email") String email, @Param("active") int active);

    @Query("select u from  User u where  u.email=:email and (u.active=1 or u.active=-1)")
    User findOneLogin(@Param("email") String email);
    @Query("SELECT COUNT(u) FROM User u WHERE u.key=?1")
    long countTokens(String token);

    @Query(value = "select * from user u  where u.key=:token and u.expired_key >= (select now())", nativeQuery = true)
    User findOneByToken(@Param("token") String token);


}
