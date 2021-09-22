
function redirect() {
    var show = document.getElementById("show-message");
    var seconds = 5;
    setInterval(function () {
        show.textContent = "Bạn sẽ được chuyển hướng sang \"Quản lý đơn hàng\" sau " + seconds + " giây";
        if (seconds == 0) {
            window.location.href = '/user/my-order';
        }
        seconds--;
    }, 1000);


}
var data = {
    "totalPrice": 0,
    "payment": "paypal"
}
window.onload = function () {
    $.ajax({
        type: 'POST',
        contentType: 'application/json',
        accept: 'application/json',
        data: JSON.stringify(data),
        headers: {'paypalSuccess':'success'},
        url: '/api/order',
        success: function (rs) {
            if(rs.id != 0)
                showSuccessMessage("Đặt hàng thành công!", "Chúng tôi đã nhận được đơn hàng của bạn.\n Cảm ơn bạn đã mua hàng.")
        }
    })
    redirect();
}