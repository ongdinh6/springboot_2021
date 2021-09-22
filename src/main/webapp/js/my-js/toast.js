//Toast thông báo lỗi khi sản phẩm đã tồn tại trong giỏ hàng
var toast = function ({title = "", type = "", message = "", duration = 3000}) {
    const main = document.getElementById('toast');
    //tao ra cac element trong toast
    const icon = {
        success: 'fas fa-check-circle',
        warning: 'fas fa-info-circle',
        error: 'fas fa-times-circle',
    }
    const iconToast = icon[type];

    if (main) {
        //tao ra mot div chua noi dung toast
        const toast = document.createElement('div');

        const autoRemove = setTimeout(function () {
            main.removeChild(toast);
        }, duration);

        toast.onclick = function (e) {
            if (e.target.closest('.fas.fa-times')) {
                main.removeChild(toast);
                clearTimeout(autoRemove);
            }
        }
        toast.innerHTML = `
            <div class="toast toast--${type}">
                    <div class="toast__icon">
                        <i class="${iconToast}"></i>
                    </div>
                    <div class="toast__content">
                        <b>${title}</b><br/>
                        <span><small style="white-space: pre-wrap">${message}</small></span>
                    </div>
                    <div class="toast__icon">
                        <i class="fas fa-times"></i>
                    </div>
             </div>
            `;
        main.appendChild(toast);
    }
}

function showSuccess() {
    toast({
        type: "success",
        title: "Thành công!",
        message: 'Sản phẩm đã được thêm vào giỏ hàng.',
        duration: 5000
    })
}

function showError() {
    toast({
        type: "error",
        title: "Thất bại!",
        message: 'Hệ thống đang gặp sự cố. Vui lòng thực hiện sau.',
        duration: 5000
    })
}

function showWarning() {
    toast({
        type: "warning",
        title: "Thông báo!",
        message: 'Vui lòng đăng nhập trước khi thêm sản phẩm vào giỏ.',
        duration: 5000
    })
}

function showSuccessMessage(title, message) {
    toast({
        type: "success",
        title: title,
        message: message,
        duration: 5000
    })
}

function showErrorMessage(title, message) {
    toast({
        type: "error",
        title: title,
        message: message,
        duration: 5000
    })
}

function showWarningMessage(title, message) {
    toast({
        type: "warning",
        title: title,
        message: message,
        duration: 5000
    })
}
