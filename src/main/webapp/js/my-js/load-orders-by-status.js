$('#statusOrderSelect').change(function () {
    var statusOrder = $(this).val();
    $.ajax({
        type: 'GET',
        data: {statusOrder: statusOrder},
        url: 'ajax-load-by-status',
        success: function (rs) {
            if (rs === "") {
                $('.table-body').html('<td colspan="6">Không có đơn hàng ở trạng thái ' + statusOrder + '!</td>');
            } else {

                $('.table-body').html(rs);

            }
        }
    })

})

$('#btnSearchByOrderID').click(function () {
    var searchParams = $('#searchByIdOrder').val() === "" ? 'null' : $('#searchByIdOrder').val();
    $.ajax({
        type: 'GET',
        data: {orderID: searchParams},
        url: 'ajax-load-by-status',
        success: function (rs) {
            if (rs === "") {
                $('.table-body').html('<td colspan="6">Không tồn tại đơn hàng có mã ' + searchParams + ' !</td>');
            } else {
                $('.table-body').html(rs);
            }
        }
    })

})
$(".table-body").on("click",".fas.fa-arrow-circle-right.icon.modal-del", function(){
    var idDeny = $(this).prop('id').split('-')[1]
    $('#btnDenyOrder-' + idDeny).click(function () {
        $.ajax({
            type: 'POST',
            data: {orderID: idDeny},
            url: '/ajax-deny-order',
            success: function (rs) {
                if (rs !== 'error') {
                    $('#exampleModal' + idDeny).modal('toggle');
                    $('.status-order-' + idDeny).text("Đã hủy");
                    showDenySuccess();
                } else {
                    alert("Hệ thống đang xảy ra lỗi! Thực hiện sau.")
                }
            }
        })
    })
})

function showDenySuccess() {
    toast({
        title: "Hủy thành công đơn hàng!",
        type: 'success',
        message: 'Đơn hàng đã được hủy.\nHãy tiếp tục mua hàng bạn nhé.',
        duration: 5000
    })
}