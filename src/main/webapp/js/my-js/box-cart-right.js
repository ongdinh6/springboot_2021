
var allLiPrice = document.getElementsByClassName('li-price');
if (allLiPrice.length > 0) {
    var tt = 0;
    var sum = 0;
    $('.li-price').each(function (index) {
        console.log($(this).text());
        tt += convert(reverseFormatNumber($(this).text(), "vi-VN"));
        sum++;
    })
    $('.total-cart').html(formatter.format(tt));
    $('#sumOfCart').text(sum);
}