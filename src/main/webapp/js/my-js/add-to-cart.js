/*
* JQUERY CHECK CÁC CASE CÓ THỂ CÓ TRONG QUÁ TRÌNH THÊM SẢN PHẨM VÀO GIỎ HÀNG
*/

/*
 * Kiểm tra sản phẩm đã có trong giỏ hay chưa?
 * Dùng ajax kiểm tra và trả về kết quả là true/false, đồng thời server (có/không) thêm vào csdl
 * Chổ này hiển thị notifications cho người dùng biết là họ nhận được gì sau khi yêu cầu
 */
// $('.btnAddToCart').click(function () {
//     let productID = $(this).val();
//     console.log(JSON.stringify({productID: productID, amount: 1}));
//     $.ajax({
//         type: 'POST',
//         data: {id: 0, productID: productID, amount: 1},
//         url: 'add-to-cart',
//         success: function (result) {
//
//             if (result === 'error') {
//                 showError();
//                 // }
//                 // else if (result === 'warning') {
//                 //showWarning();
//             } else {
//                 var userSessionForCart = document.getElementsByClassName('userSessionForCart');
//                 // if(userSessionForCart !== null)
//                 let sum = parseInt($("#sumOfCart").text(), 10) + 1;
//                 $('#sumOfCart').text(sum);
//                 showSuccess();
//                 $('.cart-list').append(result);
//                 var allLiPrice = document.getElementsByClassName('li-price');
//                 var total = 0;
//                 if (allLiPrice.length > 0) {
//                     $('.li-price').each(function (index) {
//                         console.log($(this).text());
//                         total += convert(reverseFormatNumber($(this).text(), "vi-VN"));
//                     })
//                 }
//                 $('.total-cart').html(formatter.format(total));
//             }
//         }
//     })
// })
//

//add cart v2
$('.btnAddToCart').click(function () {
    let productID = $(this).val();
    var atDetail = document.querySelector("#quantity-product-detail");
    var amount = 1;
    if(atDetail) {
        amount =  $('#quantity-product-detail').val();
    }
    $.ajax({
        type: 'POST',
        contentType: 'application/json;charset=UTF-8',
        data: JSON.stringify({"productID": productID, "amount": amount, "active": 1}),
        accept: 'application/json',
        url: '/add-to-cart',
        headers: {action: 'add'},
        success: function (rs) {
            showSuccess();
            var rsJS = JSON.stringify(rs);
            var json = JSON.parse(rsJS);
            var x = '';
            var lastPrice = 0;
            var sum = 0;
            for (i = 0; i < json.length; i++) {
                x += "<li class=\"cart-item\"><a href=\"#\" class=\"photo\"><img src=\"" + json[i].productImg + "\" class=\"cart-thumb\"></a><h6><a href=\"#\">" + json[i].productName + "</a></h6><p>" + json[i].amount + "x - <span class=\"product-price li-price\">" + formatter.format(json[i].totalPrice) + "</span></p></li>"
                lastPrice += json[i].totalPrice;
                sum++;
            }
            $('.cart-list').html(x);
            $('.total-cart').html(formatter.format(lastPrice));
            $('#sumOfCart').text(sum);
        }
    })
})

