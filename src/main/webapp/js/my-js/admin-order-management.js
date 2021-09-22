
$('.btnAccept').click(function () {
    var id = $(this).prop('id')

    $.ajax({
        type: 'PUT',
        data: {id: id, action: "accept"},
        url: "/admin/orders-manage/pending/"+id,
        success: function (rs) {
            if (rs === "error") showErrorMessage("Lỗi", "Hệ thống đang gặp sự cố. Thử lại sau!");
            if (rs === "success") {
                showSuccessMessage("Thành công", "Bạn đã xác thực đơn hàng thành cồng.\n Đơn hàng đã được thay đổi trạng thái thành 'Đang giao hàng'.", 7000)

                var seconds = 1;
                setInterval(function () {
                    if (seconds == 0) {
                        window.location.href = '/admin/orders-manage/pending'
                    }
                    seconds--;
                }, 1000);

            }
        }
    })
})

//refuse

$('.btnRefuse').click(function () {
    var id = $(this).prop('id')

    $.ajax({
        type: 'PUT',
        data: {id: id},
        url: "/admin/orders-manage/pending/"+id,
        headers: {action : 'refuse'},
        success: function (rs) {
            if (rs === "error") showErrorMessage("Lỗi", "Hệ thống đang gặp sự cố. Thử lại sau!");
            if (rs === "success") {
                showSuccessMessage("Thành công", "Từ chối đơn hàng thành công.", 7000)

                var seconds = 1;
                setInterval(function () {
                    if (seconds == 0) {
                        window.location.href = '/admin/orders-manage/pending'
                    }
                    seconds--;
                }, 1000);

            }
        }
    })
})