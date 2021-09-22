
$(function () {
    $('.loader').css('display', 'none')
    $('#btnOrder').click(function () {
        $('.loader').css('display', 'block')
        $('.loader').delay(3000).fadeOut('fast');
    })
})