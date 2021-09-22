$(function () {
    const formatter = new Intl.NumberFormat('vi-VN', {style: 'currency', currency: 'VND'});
    $(window).on('load', function () {
        $.ajax({
            type: 'GET',
            contentType: 'application/json;charset=UTF-8',
            accept: 'application/json',
            url: '/cart/all',
            success: function (rs) {
                var rsJS = JSON.stringify(rs);
                var json = JSON.parse(rsJS);
                var x = '';
                var lastPrice = 0;
                var sum = 0;
                for (i = 0; i < json.length; i++) {
                    console.log(json[i])
                    x += "<li class=\"cart-item\" id=\"li"+json[i].productID+"\"><a href=\"#\" class=\"photo\"><img src=\"" + json[i].productImg + "\" class=\"cart-thumb\"></a><h6><a href=\"#\">" + json[i].productName + "</a></h6><p>" + json[i].amount + "x - <span class=\"product-price li-price\">" + formatter.format(json[i].totalPrice) + "</span></p></li>"
                    lastPrice += json[i].totalPrice;
                    sum++;
                }
                $('.cart-list').html(x);
                $('.total-cart').html(formatter.format(lastPrice));
                $('.last-price').html(formatter.format(lastPrice));
                $('#sumOfCart').text(sum);
            }
        })
    })
})