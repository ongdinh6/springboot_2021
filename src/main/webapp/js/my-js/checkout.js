$('#btnOrder').click(function () {
    if ($('#province').val() === null || $('#district').val() === null || $('#ward').val() === null) {
        showMessageSelectProvince();
        $('#address').css('border', 'red 1px solid')
        $('.invalid-feedback').css('display', 'initial');
    } else {
        $('.invalid-feedback').css('display', 'none');
        var address = ($('#address').val() + ", " + $('#ward').val() + ", " + $('#district').val() + ", " + $('#province').val()).trim();
        var nameClient = $('#fullName').val();
        var phoneNumber = $('#phoneNumber').val();
        var totalPrice = convert(reverseFormatNumber($('#lastPrice').text(), "vi-VN"));
        var payment = $('#cash').prop('checked') === true ? 'Trực tiếp' : 'Paypal';
        // var urlAjax = payment==='Trực tiếp'?'order':'pay';
        console.log(address+", "+nameClient+", "+phoneNumber+", "+payment)
        $.ajax({
            type: 'POST',
            url: 'order',
            data: {
                address: address,
                nameClient: nameClient,
                phoneNumber: phoneNumber,
                totalPrice: totalPrice,
                payment: payment,
                paypalResponse: "false"
            },
            success: function (rs) {
                if (rs === 'error') {
                    showErrorOrder();
                } else {
                    if (rs === '/login') {
                        $('#signInModel').modal('toggle');
                    } else {
                        if (rs !== '/pay') {
                            $('div.loader').prop('display', 'block');
                            $(window).on('load', function (event) {
                                // $('body').removeClass('preloading');
                                // $('.load').delay(1000).fadeOut('fast');
                                $('.loader').delay(1000).fadeOut('fast');
                            });
                            window.location.href = rs;
                        } else {
                            //call ajax to sandbox
                            $.ajax({
                                type: 'POST',
                                url: 'pay',
                                data: {
                                    address: address,
                                    nameClient: nameClient,
                                    phoneNumber: phoneNumber,
                                    totalPrice: totalPrice,
                                    payment: payment,
                                    paypalResponse: "false"
                                },
                                success: function (rs) {
                                    $('.loader').prop('display', 'block');
                                    $(window).on('load', function (event) {
                                        // $('body').removeClass('preloading');
                                        // $('.load').delay(1000).fadeOut('fast');
                                        $('.loader').delay(1000).fadeOut('fast');
                                    });
                                    window.location.href = rs;
                                }
                            })
                        }
                    }
                }
            }
        })

    }
})

function showMessageSelectProvince() {
    toast({
        title: "Thông báo!",
        type: "warning",
        message: "Vui lòng chọn địa chỉ nhận hàng. Bỏ qua những trường đã nhập dữ liệu!",
        duration: 5000
    })
}

function showErrorOrder() {
    toast({
        title: "Thất bại!",
        type: "error",
        message: "Hệ thống đang gặp sự cố. Vui lòng thực hiện sau!",
        duration: 5000
    })
}

