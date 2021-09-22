package nlu.fit.cellphoneapp.entities;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;
import nlu.fit.cellphoneapp.DTOs.CartItemRequest;
import nlu.fit.cellphoneapp.helper.DateHelper;
import nlu.fit.cellphoneapp.helper.StringHelper;
import nlu.fit.cellphoneapp.receiver.RegisterForm;
import nlu.fit.cellphoneapp.receiver.UpdateInfoForm;
import org.hibernate.annotations.LazyCollection;
import org.hibernate.annotations.LazyCollectionOption;

import javax.persistence.*;
import javax.servlet.http.HttpSession;
import java.util.*;
import java.util.regex.Pattern;

@Entity
@Table(name = "user")
@Getter
@Setter
public class User {
    public static final String SESSION = "currentUser";


    public enum ROLE {
        CONSUMEER(1), ADMIN(2);
        private final int value;

        ROLE(int value) {
            this.value = value;
        }

        public int value() {
            return value;
        }
    }

    public enum ACTIVE {
        ACTIVE(1), INACTIVE(2), UNVERTIFIED(-1);
        private final int value;

        ACTIVE(int constValue) {
            this.value = constValue;
        }

        public int value() {
            return value;
        }
    }

    public static final int USER_ROLE = 1;
    public static final int ADMIN_ROLE = 2;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;
    private String email;
    private String password;
    @Column(name = "full_name")
    private String fullName;
    private String avatar;
    private String phone;
    private String address;
    private String gender;
    private Date birth;
    private String key;
    @Column(name = "expired_key")
    private Date expiredKey;
    private int active;
    private int role;
    private boolean isRequestUnblock = false;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL,
            fetch = FetchType.EAGER)
    private Set<Favorite> favorites;
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL,
            fetch = FetchType.LAZY)
    private Set<Review> reviews;
    @OneToMany(
            mappedBy = "user",
            cascade = CascadeType.ALL,
            orphanRemoval = true,
            fetch = FetchType.EAGER
    )
    private Set<CartItem> cartItems;
    @OneToMany(
            mappedBy = "user",
            cascade = CascadeType.ALL,
            orphanRemoval = true
    )
    @LazyCollection(LazyCollectionOption.FALSE)
    private Collection<Order> orders = new HashSet<>();

    public String toStringRole() {
        switch (this.role) {
            case USER_ROLE:
                return "USER";
            case ADMIN_ROLE:
                return "ADMIN";
        }
        return null;
    }

    //  https://regex101.com/codegen?language=java
    public static boolean validName(String name) {
        String expression = "^\\p{L}+[\\p{L}\\p{Z}\\p{P}]{0,}";
        return name.matches(expression);
    }

    public static boolean validPassword(String password) {
        String expression = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#&()–[{}]:;',?/*~$^+=<>]).{8,20}$";
        return password.matches(expression);
    }

    public static boolean validPhone(String phone) {
        final String regex = "(84|0[3|5|7|8|9])+([0-9]{8})\\b";
        return phone.matches(regex);
    }

    public static boolean validEmail(String email) {
        String emailRegex = "^[a-zA-Z0-9_+&*-]+(?:\\." + "[a-zA-Z0-9_+&*-]+)*@" + "(?:[a-zA-Z0-9-]+\\.)+[a-z"
                + "A-Z]{2,7}$";

        Pattern pat = Pattern.compile(emailRegex);
        if (email == null)
            return false;
        return pat.matcher(email).matches();
    }

    public static String validInfo(RegisterForm registerForm) {
        List<String> toCheck = new ArrayList<>();
        toCheck.add(registerForm.newemail);
        toCheck.add(registerForm.newfullname);
        toCheck.add(registerForm.newpassword);
        toCheck.add(registerForm.confirmpassword);
        if (StringHelper.isNoValue(toCheck)) {
            return "emptyfield";
        } else if (User.validGender(registerForm.newgender)) {
            return "emptyfield";
        } else if (!User.validName(registerForm.newfullname)) {
            return "errname";
        } else if (!User.validPassword(registerForm.newpassword)) {
            return "errpass";
        } else if (!registerForm.newpassword.equals(registerForm.confirmpassword)) {
            return "confirmpass";
        } else if (!User.validEmail(registerForm.newemail)) {
            return "errmail";
        }
        return null;
    }


    public static String toStringGender(int gender) {
        return gender == 1 ? "Nam" : "Nữ";
    }

    public static boolean validGender(int gender) {
        return gender == 1 || gender == 2;
    }

    public static boolean validGender(String gender) {
        return gender.equals("Nam") || gender.equals("Nữ");
    }

    public void updateInfo(UpdateInfoForm form) {
        this.fullName = form.fullName;
        System.out.println(form.birth);
        this.birth = DateHelper.convertToDate(form.birth, "yyyy-MM-dd");
        System.out.println(this.birth);
        this.address = form.address;
        this.phone = form.phone;
        this.gender = form.gender;
    }

    public String toStringBirth() {
        return DateHelper.convertToString(this.birth, "yyyy-MM-dd");
    }

    public double getTotalPrice() {
        double rs = 0.0;
        for (CartItem c : cartItems) {
            rs += (c.getAmount() * c.getProduct().getPrice());
        }
        return rs;
    }

    public static boolean checkUserSession(HttpSession session) {
        if (null != (User) session.getAttribute(SESSION)) return true;
        return false;
    }

    public boolean updateCart(CartItemRequest cartUpdate) {
        for (CartItem c : cartItems) {
            if (c.getId() == cartUpdate.getId()) {
                c.setAmount(cartUpdate.getAmount());
                c.updateTotalPrice();
                return true;
            }
        }
        return false;
    }

    public boolean hasFavoriteProduct(int productId) {
        for (Favorite favorite : favorites) {
            if (favorite.getProduct().getId() == productId)
                return true;
        }
        return false;
    }

    public void addFavorite(Favorite favorite) {
        this.favorites.add(favorite);
    }

    public Favorite removeFavorite(int productId) {
        for (Favorite favorite : favorites) {
            if (favorite.getProduct().getId() == productId) {
                this.favorites.remove(favorite);
                return favorite;
            }
        }
        return null;
    }

    public Collection<CartItemRequest> appendCartSession(Collection<CartItemRequest> cartSession) {
        Collection<CartItemRequest> collectionNewCartItem = new HashSet<CartItemRequest>();
        int i = 0;
        while (i < cartSession.size()) {
            boolean isEquals = false;
            CartItemRequest cs = (CartItemRequest) cartSession.toArray()[i];
            int requestAmount = cs.getAmount();
            for (CartItem c : cartItems) {
                if (c.getProduct().getId() == cs.getProductID()) {
                    c.setAmount(requestAmount);
                    c.updateTotalPrice();
                    isEquals = true;
                }
            }
            i++;
            if (isEquals == false) {
                collectionNewCartItem.add(cs);
            }
        }
        return collectionNewCartItem;
    }

    public boolean removeCartItem(int id) {
        for (CartItem c : cartItems) {
            if (c.getId() == id) {
                cartItems.remove(c);
                return true;
            }
        }
        return false;
    }

    public CartItem updateCartItem(CartItem c, CartItem cDB) {
        c.setAmount(cDB.getAmount());
        c.setProduct(cDB.getProduct());
        c.setActive(cDB.getActive());
        c.setUser(cDB.getUser());
        c.setTotalPrice(cDB.getTotalPrice());
        c.setId(cDB.getId());
        return c;
    }

    public void updateOrderInfo(Order o, Order orderDB) {
        o.setOrderStatus(orderDB.getOrderStatus());
        o.setActive(orderDB.getActive());
        o.setPayment(orderDB.getPayment());
        o.setUser(orderDB.getUser());
        o.setPhoneNumberOfClient(orderDB.getPhoneNumberOfClient());
        o.setNameOfClient(orderDB.getNameOfClient());
        o.setId(orderDB.getId());
        o.setCreatedDate(orderDB.getCreatedDate());
        o.setAddress(orderDB.getAddress());
        o.setTotalPrice(orderDB.getTotalPrice());
        o.setOrderDetails(orderDB.getOrderDetails());
    }

    public Collection<Order> checkAndSetOrderUserDB(Collection<Order> collectionOrderUserDB) {
        orders = collectionOrderUserDB;
        return orders;
    }

}
