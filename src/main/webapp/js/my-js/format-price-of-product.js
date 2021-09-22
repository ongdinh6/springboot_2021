const formatter = new Intl.NumberFormat('vi-VN', {style: 'currency', currency: 'VND'});

function formatCurrency(number){
    var n = number.split('').reverse().join("");
    var n2 = n.replace(/\d\d\d(?!$)/g, "$&,");
    return  n2.split('').reverse().join('') + 'đ';
}
function reverseFormatNumber(val,locale){
    var group = new Intl.NumberFormat(locale).format(1111).replace(/1/g, '');
    var decimal = new Intl.NumberFormat(locale).format(1.1).replace(/1/g, '');
    var reversedVal = val.replace(new RegExp('\\' + group, 'g'), '');
    reversedVal = reversedVal.replace(new RegExp('\\' + decimal, 'g'), '.');
    return Number.isNaN(reversedVal)?0:reversedVal;
}


$.fn.formatCurrency = function () {
    this.each(function () {
        $(this).text(formatter.format($(this).text()));
        $(this).val(reverseFormatNumber($(this).val(), "vi-VN"));
    });
    return this;
};
$('.product-price').formatCurrency();

