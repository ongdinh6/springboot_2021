package nlu.fit.cellphoneapp.services;

import nlu.fit.cellphoneapp.entities.User;

import java.util.Collection;


public interface IUserService {
    boolean isEmailUnique(String email);

    User findOneByEmail(String email);

    boolean save(User user);

    boolean isTokenUnique(String token);

    User findOneByLogin(String email, String password);

    User findOneByToken(String token);

    User findOneByEmailActive(String email, int active);

    boolean isCurPassword(String curPassword);

    Collection<User> getAllListUser();
    User findOneById(int id);
}
