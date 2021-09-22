function convert(currency) {

    // Using replace() method
    // to make currency string suitable
    // for parseFloat() to convert
    var temp = currency.replace(/[^0-9.-]+/g, "");

    // Converting string to float
    // or double and return
    return parseFloat(temp);
}

// $('.tr-update').change(function () {
//     //tính giá theo số lượng khi có sự cập nhật
//     var cartItemID = $(this).prop('id');
//     var productID = $(this).find('p.product-price.current-price-product').prop('id');
//     var amount = $(this).find('input.c-input-text.qty.text').val();
//     var currentPrice = $(this).find('p.product-price.current-price-product').text();
//     var total = amount * convert(reverseFormatNumber(currentPrice, "vi-VN"));
//     $(this).find('p.product-price.total-by-product').html(formatter.format(total));
//
//     $.ajax({
//         type: 'POST',
//         data: {id: cartItemID, amount: amount, totalPrice: total, productID: productID},
//         url: 'add-to-cart',
//         success: function (result) {
//
//         }
//     })
//
//     //tổng cộng giá theo số lượng
//     var allTotalPriceByProductID = document.querySelectorAll('.total-by-product');
//     let result = 0;
//     for (var i = 0, len = allTotalPriceByProductID.length | 0; i < len; i = i + 1 | 0) {
//         result += convert(reverseFormatNumber(allTotalPriceByProductID[i].textContent, "vi-VN"));
//     }
//     $('.total-price').html(formatter.format(result));
//
//     //giá cuối cùng (Thành tiền)
//     var lastPrice = result - convert(reverseFormatNumber($('.discount-price').text(), "vi-VN"));
//     $('.last-price').html(formatter.format(lastPrice));
// })
//
// var sumAmount = $('#sumOfCart').text();
// //xóa sản phẩm
var cartID = 0;
$('.remove-action').click(function () {
    cartID = $(this).attr('value');
    var amountRemove = $(this).attr('name');
    // let resetAmount = parseInt(sumAmount - 1);
    let totalPriceBefore = convert(reverseFormatNumber($('.total-price').text(), "vi-VN"));
    let priceRemove = convert($(this).attr('alt'));
    let resetTotalPrice = totalPriceBefore - priceRemove;
    $('#btnDeleteModalConfirm').prop('value', cartID)
    $('#amountRemove').text(amountRemove)
    // $('#resetAmount').text(resetAmount)
    $('#totalPriceBefore').text(totalPriceBefore)
    $('#priceRemove').text(priceRemove)
    $('#resetTotalPrice').text(resetTotalPrice)

})
$('#btnDeleteModalConfirm').click(function () {
    cartID = $(this).attr('value')
    var sumOfCart = $('#sumOfCart').text()
    let resetAmount = $('#resetAmount').text()
    let totalPriceBefore = reverseFormatNumber($('.total-all-price').text(), "vi-VN")
    let priceRemove = reverseFormatNumber($('#totalProductPriceAfterUpdate'+cartID).text(), "vi-VN")
    let resetTotalPrice = convert(totalPriceBefore)-convert(priceRemove);
    $.ajax({
        type: 'DELETE',
        data: {productID: cartID},
        url: 'cart/delete',
        success: function (result) {
            if (result === "success") {
                $('#removeCartItemModal').modal('toggle');
                $('.tr' + cartID).remove();
                $('#sumOfCart').text(sumOfCart-1);
                $('#li' + cartID).remove();
                $('.total-all-price').html(formatter.format(resetTotalPrice));
                $('.total-cart').html(formatter.format(resetTotalPrice));
                $('.last-price').html(formatter.format(resetTotalPrice - convert(reverseFormatNumber($('.discount-price').text(), "vi-VN"))));
                deleteSuccess();
            } else if(result === "error"){
                showFailDelete();
            }else{
                window.location.href = result;
            }
        }
    })
})


function deleteSuccess() {
    toast({
        type: 'success',
        title: "Xóa thành công!",
        message: "Sản phẩm vừa chọn đã được xóa khỏi giỏ hàng.",
        duration: 3000
    })
}

function showFailDelete() {
    toast({
        title: 'Thất bại!',
        type: "error",
        message: "Hệ thống đang xảy ra lỗi. Không thể xóa.",
        duration: 3000
    })
}

//update cart v2
$('.tr-update').change(function () {
    alert("auto-inc")
    var productID = $(this).find('p.product-price.current-price-product').prop('id');
    var amount = $(this).find('input.c-input-text.qty.text').val();
    $.ajax({
        type: 'POST',
        contentType: 'application/json;charset=UTF-8',
        data: JSON.stringify({"productID": productID, "amount": amount, "active": 1}),
        accept: 'application/json',
        url: 'add-to-cart',
        headers: {action: 'update'},
        success: function (rs) {
            var rsJS = JSON.stringify(rs);
            var json = JSON.parse(rsJS);
            var totalAllCart = 0;
            var x = '';
            var lastPrice = 0;
            for (let i = 0; i < json.length; i++) {
                var rowUpdate = json[i].productID;
                totalAllCart += json[i].totalPrice;
                x += "<li class=\"cart-item\" id=\"li"+json[i].productID+"\"><a href=\"#\" class=\"photo\"><img src=\"" + json[i].productImg + "\" class=\"cart-thumb\"></a><h6><a href=\"#\">" + json[i].productName + "</a></h6><p>" + json[i].amount + "x - <span class=\"product-price li-price\">" + formatter.format(json[i].totalPrice) + "</span></p></li>"
                lastPrice += json[i].totalPrice;
            }
            $('.cart-list').html(x);
            $('.total-cart').text(formatter.format(lastPrice));
            $('.total-all-price').text(formatter.format(totalAllCart));
            $('.last-price').text(formatter.format(totalAllCart - convert($('.discount-price').text())));
        }
    })
    var price = convert(reverseFormatNumber($('#' + productID + '').text(), "vi-VN"));
    $('#totalProductPriceAfterUpdate' + productID + '').text(formatter.format(price * parseInt(amount)));

})

$(window).on('load', function () {
    $.ajax({
        type: 'GET',
        contentType: 'application/json;charset=UTF-8',
        accept: 'application/json',
        url: '/cart/all',
        success: function (rs) {
            var rsJS = JSON.stringify(rs);
            var json = JSON.parse(rsJS);
            var totalAllCart = 0;
            for (let i = 0; i < json.length; i++) {
                var rowLoad = json[i].productID;
                $('#' + rowLoad + '').text(formatter.format((json[i].totalPrice / json[i].amount)));
                totalAllCart += json[i].totalPrice;
            }
            $('.total-all-price').text(formatter.format(totalAllCart));
            $('.last-price').text(formatter.format(totalAllCart - convert($('.discount-price').text())));
        }
    })
})
