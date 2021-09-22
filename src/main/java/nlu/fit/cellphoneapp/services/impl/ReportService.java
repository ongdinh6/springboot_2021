package nlu.fit.cellphoneapp.services.impl;

import nlu.fit.cellphoneapp.entities.Order;
import nlu.fit.cellphoneapp.helper.DateHelper;
import nlu.fit.cellphoneapp.repositories.custom.ReportRepository;
import nlu.fit.cellphoneapp.services.IReportService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.List;

@Service
public class ReportService implements IReportService {
    @Autowired
    ReportRepository reportRepository;

    @Override
    public String getPaymentData(int type, String from, String to) {
        Date fromDate = DateHelper.convertToDate(from, "yyyy-MM-dd");
        Date todate = DateHelper.convertToDate(to, "yyyy-MM-dd");
        StringBuilder sb = new StringBuilder();
        List<String> listMonths = DateHelper.getMonthsBetween(from, to);
        if (listMonths.size() == 1) {
            sb.append(listMonths.get(0) + "\t");
            sb.append(reportRepository.getPaymentDataByDate(type, from, to, Order.PAYMENT_TYPE.OFFLINE.value()));
            sb.append(reportRepository.getPaymentDataByDate(type, from, to, Order.PAYMENT_TYPE.ONLINE.value()));
        } else {
            for (int i = 0; i < listMonths.size(); i++) {
                sb.append(listMonths.get(i) + "\t");
                if (i == 0) {
                    sb.append(reportRepository.getPaymentDataByDate(type, from, DateHelper.convertToString(DateHelper.getLastDayMonth(fromDate)), Order.PAYMENT_TYPE.OFFLINE.value()));
                    sb.append("\t");
                    sb.append(reportRepository.getPaymentDataByDate(type, from, DateHelper.convertToString(DateHelper.getLastDayMonth(fromDate)), Order.PAYMENT_TYPE.ONLINE.value()));
                    sb.append(System.lineSeparator());
                } else if (i == listMonths.size() - 1) {
                    sb.append(reportRepository.getPaymentDataByDate(type, DateHelper.convertToString(DateHelper.getFristDayMonth(todate)), to, Order.PAYMENT_TYPE.OFFLINE.value()));
                    sb.append("\t");
                    sb.append(reportRepository.getPaymentDataByDate(type, DateHelper.convertToString(DateHelper.getFristDayMonth(todate)), to, Order.PAYMENT_TYPE.ONLINE.value()));
                } else {
                    sb.append(reportRepository.getPaymentDataByMonthYear(type, DateHelper.getMonthOfMMYYYY(listMonths.get(i)), DateHelper.getYearhOfMMYYYY(listMonths.get(i)), Order.PAYMENT_TYPE.OFFLINE.value()));
                    sb.append("\t");
                    sb.append(reportRepository.getPaymentDataByMonthYear(type, DateHelper.getMonthOfMMYYYY(listMonths.get(i)), DateHelper.getYearhOfMMYYYY(listMonths.get(i)), Order.PAYMENT_TYPE.OFFLINE.value()));
                    sb.append(System.lineSeparator());
                }
            }
        }
        return sb.toString();
    }

    @Override
    public String getCategoryData(int category, int type, String start, String end) {
        StringBuilder sb = new StringBuilder();
        List<String> result = reportRepository.getCategoryData(category, type, start, end);
        for (int i = 0; i < result.size(); i++) {
            if (i == result.size() - 1) {
                sb.append(result.get(i));
            } else {
                sb.append(result.get(i));
                sb.append(System.lineSeparator());
            }
        }
        return sb.toString();
    }
}
