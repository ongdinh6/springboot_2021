package nlu.fit.cellphoneapp.services.impl;

import nlu.fit.cellphoneapp.entities.User;
import nlu.fit.cellphoneapp.others.BcryptEncoder;
import nlu.fit.cellphoneapp.repositories.interfaces.IUserRepository;
import nlu.fit.cellphoneapp.services.IUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collection;


@Service

public class UserServiceImpl implements IUserService {
    @Autowired
    IUserRepository userRepo;

    @Override
    public boolean isEmailUnique(String email) {
        return userRepo.findOneByEmail(email) == null;
    }

    @Override
    public User findOneByEmail(String email) {
        return userRepo.findOneByEmail(email);
    }

    @Override
    @Transactional(propagation = Propagation.REQUIRED, rollbackFor = Exception.class)
    public boolean save(User user) {
        try {
            userRepo.save(user);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public boolean isTokenUnique(String token) {
        return userRepo.countTokens(token) >= 1;
    }

    @Override
    public User findOneByLogin(String email, String password) {
        User user;
        if ((user = userRepo.findOneByEmailActive(email, User.ACTIVE.ACTIVE.value())) == null &&
                (user = userRepo.findOneByEmailActive(email, User.ACTIVE.UNVERTIFIED.value())) == null)
            return null;
        else {
            if (BcryptEncoder.matches(password, user.getPassword())) return user;
            else return null;
        }
    }

    public User findOneByEmailActive(String email, int active) {
        return userRepo.findOneByEmailActive(email, active);
    }

    @Override
    public boolean isCurPassword(String curPassword) {
        return false;
    }

    @Override
    public Collection<User> getAllListUser() {
        return userRepo.findAll();
    }

    @Override
    public User findOneById(int id) {
        return userRepo.getOne(id);
    }


    @Override
    public User findOneByToken(String token) {
        return userRepo.findOneByToken(token);
    }


}
