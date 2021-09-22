package nlu.fit.cellphoneapp.helper;

import java.text.DecimalFormat;
import java.text.NumberFormat;

public class NumberHelper {
    public static String format(double input) {
        NumberFormat formatter = new DecimalFormat("0");
        return formatter.format(input);
    }
}
