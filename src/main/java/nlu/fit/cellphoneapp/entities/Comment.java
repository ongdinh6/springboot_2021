package nlu.fit.cellphoneapp.entities;

import lombok.Getter;
import lombok.Setter;
import nlu.fit.cellphoneapp.helper.DateHelper;

import javax.persistence.*;
import java.util.Date;

@Entity
@Table(name = "comment")
@Getter
@Setter
public class Comment {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private int id;
    @ManyToOne(fetch = FetchType.LAZY)
    private Review review;
    @ManyToOne(fetch = FetchType.LAZY)
    private User user;
    @Column(name = "created_date")
    private Date createdDate;
    private String content;
    private Integer active;

    public String toStringCreatedDate() {
        return DateHelper.convertToString(this.createdDate, "dd/MM/yyyy");
    }
}
