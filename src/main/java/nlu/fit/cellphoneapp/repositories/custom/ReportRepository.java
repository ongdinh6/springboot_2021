package nlu.fit.cellphoneapp.repositories.custom;

import lombok.AllArgsConstructor;
import org.springframework.stereotype.Repository;

import javax.persistence.*;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;

@Repository
@AllArgsConstructor
public class ReportRepository {
    @PersistenceContext(type = PersistenceContextType.EXTENDED)
    private EntityManager entityManager;

    public long getPaymentDataByMonthYear(int type, int month, int year, String payment) {
        Long result = null;
        StringBuilder sb = new StringBuilder();
        if (type == 1) {
            sb.append("SELECT SUM(od.total_price) ");
        } else {
            sb.append("SELECT SUM(od.amount) ");
        }
        sb.append("FROM order_detail od " +
                "JOIN `order` o ON o.active=1 AND o.id=od.order_id AND o.`status`='Giao thành công' ");
        sb.append("WHERE MONTH(created_date)=:month AND YEAR(created_date) =:year AND o.payment=:payment ");
        String sql = sb.toString();
        Query query = entityManager.createNativeQuery(sql).setParameter("month", month).setParameter("year", year).setParameter("payment", payment);
        if (query.getSingleResult() != null) {
            result = ((BigDecimal) query.getSingleResult()).longValue();
        }
        return result == null ? 0 : result;
    }

    public long getPaymentDataByDate(int type, String start, String end, String payment) {
        Long result = null;
        StringBuilder sb = new StringBuilder();
        if (type == 1) {
            sb.append("SELECT SUM(od.total_price) ");
        } else {
            sb.append("SELECT SUM(od.amount) ");
        }
        sb.append("FROM order_detail od " +
                "JOIN `order` o ON o.active=1 AND o.id=od.order_id AND o.`status`='Giao thành công' ");
        sb.append("WHERE o.created_date >=:start AND o.created_date <=:end AND o.payment=:payment ");
        String sql = sb.toString();
        Query query = entityManager.createNativeQuery(sql).setParameter("start", start)
                .setParameter("end", end)
                .setParameter("payment", payment);
        if (query.getSingleResult() != null) {
            result = ((BigDecimal) query
                    .getSingleResult()).longValue();
        }
        return result == null ? 0 : result;
    }

    public List<String> getCategoryData(int category, int type, String start, String end) {
        List<String> result = new ArrayList<>();
        StringBuilder sb = new StringBuilder();
        String sumCol;
        if (type == 1) {
            sumCol = "od.total_price";
        } else {
            sumCol = "od.amount";
        }
        sb.append(
                "JOIN order_detail od ON od.product_id=pr.id " +
                        "JOIN `order` o ON o.active=1 AND o.`status`=\"Giao thành công\" AND od.order_id=o.id " +
                        "WHERE o.created_date >=:start AND o.created_date <=:end "
        );
        if (category == 1) {
            sb.insert(0, "SELECT b.`name`,SUM(" + sumCol + ") FROM brand b JOIN product pr ON pr.brand_id=b.id AND b.active=1 ");
            sb.append("GROUP BY b.id");
        } else if (category == 2) {
            sb.insert(0, "SELECT p.capacity,SUM(" + sumCol + ") FROM pin p " +
                    "JOIN product pr ON pr.pin_id=p.id AND p.active=1 ");
            sb.append("GROUP BY p.id");
        } else if (category == 3) {
            sb.insert(0, "SELECT r.capacity,SUM(" + sumCol + ") FROM ram r " +
                    "JOIN product pr ON pr.ram_id=r.id AND r.active=1 ");
            sb.append("GROUP BY r.id");
        } else {
            sb.insert(0, "SELECT r.capacity,SUM(" + sumCol + ") FROM rom r " +
                    "JOIN product pr ON pr.rom_id=r.id AND r.active=1");
            sb.append("GROUP BY r.id");
        }
        String sql = sb.toString();
        Query query = entityManager.createNativeQuery(sql).setParameter("start", start)
                .setParameter("end", end);
        if (query.getResultList() != null) {
            List<Object[]> resultSet = query.getResultList();
            resultSet.stream().forEach((record) -> {
                result.add(record[0] + "\t" + ((BigDecimal) record[1]).longValue());
            });
        }

        return result;
    }
}
