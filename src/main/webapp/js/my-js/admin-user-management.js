

$('.btnRemove').click(function () {
        let id = $(this).prop('id')
        $.ajax({
            type: 'PUT',
            data: {id: id},
            url: '/admin/users-manage/block/'+id,
            success: function (rs) {
                if(rs === 'error') showErrorMessage("Lỗi", "Hệ thống hiện đang gặp sự cố. Hãy thử lại sau!")
                if(rs === 'success') {
                    showSuccessMessage("Thành công", "Khóa tài khoản người dùng thành công.\n Người dùng sẽ không truy cập vào website và tiến hành đặt hàng được nữa!");
                    var seconds = 1;
                    setInterval(function () {
                        if (seconds == 0) {
                            window.location.href = '/admin/users-manage'
                        }
                        seconds--;
                    }, 1000);
                }

            }
        })
})