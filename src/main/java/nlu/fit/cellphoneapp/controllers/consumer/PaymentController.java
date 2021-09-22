package nlu.fit.cellphoneapp.controllers.consumer;


import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import nlu.fit.cellphoneapp.config.PaypalPaymentIntent;
import nlu.fit.cellphoneapp.config.PaypalPaymentMethod;
import nlu.fit.cellphoneapp.entities.CartItem;
import nlu.fit.cellphoneapp.entities.Order;
import nlu.fit.cellphoneapp.entities.OrderDetail;
import nlu.fit.cellphoneapp.others.Link;
import nlu.fit.cellphoneapp.services.PaypalService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import com.paypal.api.payments.Links;
import com.paypal.api.payments.Payment;
import com.paypal.base.rest.PayPalRESTException;

@Controller
public class PaymentController {

    public static final String URL_PAYPAL_SUCCESS = "/success";
    public static final String URL_PAYPAL_CANCEL = "/cancel";
    public static boolean successed = false;

    private Logger log = LoggerFactory.getLogger(getClass());

    @Autowired
    private PaypalService paypalService;


    @PostMapping("/pay")
    @ResponseBody
    public String pay(@RequestBody Order order, HttpServletRequest request){
        String cancelUrl = Link.createAbsolutePath(request, URL_PAYPAL_CANCEL);
        String successUrl = Link.createAbsolutePath(request, URL_PAYPAL_SUCCESS);
        try {
            Payment payment = paypalService.createPayment(
                    order.getTotalPrice()/23000,
                    "USD",
                    PaypalPaymentMethod.paypal,
                    PaypalPaymentIntent.sale,
                    "payment description",
                    cancelUrl,
                    successUrl);
            for(Links links : payment.getLinks()){
                if(links.getRel().equals("approval_url")){
                    successed = true;
                    return links.getHref();
                }
            }
        } catch (PayPalRESTException e) {
            log.error(e.getMessage());
        }
        return "redirect:/";
    }

    @GetMapping(URL_PAYPAL_CANCEL)
    public String cancelPay(){
        return "consumer/paypal-cancel";
    }

    @GetMapping(URL_PAYPAL_SUCCESS)
    public String successPay(@RequestParam("paymentId") String paymentId, @RequestParam("PayerID") String payerId){
        try {
            Payment payment = paypalService.executePayment(paymentId, payerId);
            if(payment.getState().equals("approved")){
                return "consumer/paypal-success";
            }
        } catch (PayPalRESTException e) {
            log.error(e.getMessage());
        }
        return "redirect:/";
    }

}