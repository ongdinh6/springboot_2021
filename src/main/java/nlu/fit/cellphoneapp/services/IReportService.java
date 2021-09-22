package nlu.fit.cellphoneapp.services;

public interface IReportService {
    String getPaymentData(int type, String start, String end);

    String getCategoryData(int category, int type, String start, String end);


}
