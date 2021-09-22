package nlu.fit.cellphoneapp.helper;

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.time.LocalDate;
import java.time.YearMonth;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

public class DateHelper {


    public static int monthsBetween(Date a, Date b) {
        long monthsBetween = ChronoUnit.MONTHS.between(
                YearMonth.from(convertToLocalDate(a)),
                YearMonth.from(convertToLocalDate(b))
        );
        return (int) monthsBetween;
    }

    public static List<String> getMonthsBetween(String from, String to) {
        // List to be populated and returned
        List<String> dateList = new ArrayList<>();

        // Formatter for the input
        DateFormat inputFormatter = new SimpleDateFormat("yyyy-MM-dd");

        // Formatter for the output
        DateFormat outputFormatter = new SimpleDateFormat("MM-yyyy");

        // Parse strings to LocalDate instances
        Date startDate = null;
        Date endDate = null;
        try {
            startDate = inputFormatter.parse(from);
            endDate = inputFormatter.parse(to);
        } catch (ParseException e) {
            e.printStackTrace();
        }
        // Calendar to start with
        Calendar startWith = Calendar.getInstance();
        startWith.setTime(startDate);
        startWith.set(Calendar.DAY_OF_MONTH, 1);

        for (Calendar calendar = startWith; calendar.getTime().getTime() <= endDate.getTime(); calendar
                .add(Calendar.MONTH, 1)) {
            dateList.add(outputFormatter.format(calendar.getTime()));
        }

        return dateList;
    }

    public static int getMonthOfMMYYYY(String input) {
        if (input.charAt(0) == '0') {
            return input.split("-")[0].charAt(1) - '0';
        } else {
            return Integer.parseInt(input.split("-")[0]);
        }
    }

    public static int getYearhOfMMYYYY(String input) {
        return Integer.parseInt(input.split("-")[1]);
    }


    public static Date addMinute(int minute) {
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.MINUTE, minute);
        return cal.getTime();
    }

    public static Date getMonthAgo(int month) {
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.MONTH, -month);
        return cal.getTime();
    }

    public static List<Date> getHalfYearAgo() {
        List<Date> dates = new ArrayList<>();
        for (int i = 6; i >= 1; i--) {
            dates.add(getMonthAgo(i));
        }
        return dates;
    }

    public static int getMonth(Date date) {
        return date.toInstant().atZone(ZoneId.systemDefault()).toLocalDate().getMonthValue();
    }

    public static int getYear(Date date) {
        return date.toInstant().atZone(ZoneId.systemDefault()).toLocalDate().getYear();
    }


    public static Date getFristDayMonth(Date date) {
        Calendar cal = Calendar.getInstance();
        cal.setTime(date);
        cal.set(Calendar.DAY_OF_MONTH, cal.getActualMinimum(Calendar.DAY_OF_MONTH));
        return cal.getTime();
    }

    public static Date getLastDayMonth(Date date) {
        Calendar cal = Calendar.getInstance();
        cal.setTime(date);
        cal.set(Calendar.DAY_OF_MONTH, cal.getActualMaximum(Calendar.DAY_OF_MONTH));
        return cal.getTime();
    }

    public static String convertToString(Date date) {
        return new SimpleDateFormat("yyyy-MM-dd").format(date);
    }

    public static String convertToString(Date date, String pattern) {
        return new SimpleDateFormat(pattern).format(date);
    }

    public static Date convertToDate(String input, String pattern) {
        try {
            return new SimpleDateFormat(pattern).parse(input);
        } catch (ParseException e) {
            return null;
        }
    }

    public static LocalDate convertToLocalDate(Date dateToConvert) {
        return Instant.ofEpochMilli(dateToConvert.getTime())
                .atZone(ZoneId.systemDefault())
                .toLocalDate();
    }
}
