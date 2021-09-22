console.log();
$.fn.serializeObject = function () {
    var o = {};
    var a = this.serializeArray();
    $.each(a, function () {
        if (o[this.name]) {
            if (!o[this.name].push) {
                o[this.name] = [o[this.name]];
            }
            o[this.name].push(this.value || "");
        } else {
            o[this.name] = this.value || "";
        }
    });
    return o;
};

function resetRegisterPass() {
    $("#newpassword").val("");
    $("#confirmpassword").val("");
}

function resetRegisterInput() {
    $("#newemail").val("");
    $("#newfullname").val("");
    $("#newpassword").val("");
    $("#confirmpassword").val("");
}

function resetResetPassIntput() {
    $("#newpass").val("");
    $("#confirmpass").val("");
}

function showMessage(isSuccess, message, carrier) {
    if (isSuccess) {
        if (carrier.hasClass("error")) carrier.removeClass("error");
        carrier.addClass("success");
        carrier.hide().text(message).fadeIn("slow");
    } else {
        if (carrier.hasClass("success")) carrier.removeClass("success");
        carrier.addClass("error");
        carrier.hide().text(message).fadeIn("slow");
    }
}

$("#register-form").submit(function (e) {
    var btn = $("#btn-register");
    var carrier = $("#show-register-message");
    e.preventDefault();
    $.ajax({
        type: "POST",
        data: JSON.stringify($(this).serializeObject()),
        contentType: "application/json",
        accept: "text/plain",
        url: "/register",
        beforeSend: function () {
            showMessage(true, "Đang xử lý", carrier);
            btn.prop("disabled", true);
        },
        success: function (result) {
            console.log(result);
            switch (result) {
                case "emptyfield":
                    showMessage(false, "Hãy điền đủ các trường", carrier);
                    break;
                case "errname":
                    showMessage(false, "Họ và tên của bạn không hợp lệ", carrier);
                    break;
                case "errmail":
                    showMessage(false, "Email của bạn không hợp lệ", carrier);
                    break;
                case "errmailexist":
                    showMessage(false, "Email của bạn đã tồn tại", carrier);
                    break;
                case "confirmpass":
                    showMessage(false, "Mật khẩu nhập lại không trùng khớp", carrier);
                    break;
                case "errpass":
                    showMessage(
                        false,
                        "Mật khẩu phải nhiều hơn 8 ký tự,có ít nhất 1 ký thường,hoa,số,đặc biệt",
                        carrier
                    );
                    break;
                case "success":
                    resetRegisterInput();
                    showMessage(
                        true,
                        "Đăng ký thành công.",
                        carrier
                    );
                    setTimeout(function () {
                        $("#createAccountModel").modal("hide");
                        $("#signInModel").modal("show");
                    }, 1500);
                    break;
                case "errsendmail":
                    showMessage(false, "Đã có lỗi xảy ra khi gửi mail", carrier);
                    break;
                default:
                    showMessage(false, "Đã xảy ra lỗi", carrier);
                    break;
            }
        },
        error: function (request, status, error) {
            showMessage(false, "Đã có lỗi xảy ra với hệ thống", carrier);
        },
        complete: function () {
            btn.prop("disabled", false);
        },
    });
});
$("#login-form").submit(function (e) {
    e.preventDefault();
    var btn = $("#btn-login");
    var carrier = $("#show-login-message");
    var password = $("#password");
    var unblockRequest = $("#unblockRequest")//17092021
    $.ajax({
        context:this,
        type: "POST",
        data: $(this).serialize(),
        accept: "text/plain",
        url: "/login",
        beforeSend: function () {
            showMessage(true, "Đang xử lý", carrier);
            btn.prop("disabled", true);
        },
        success: function (result) {
            console.log(result);
            switch (result) {
                case "emptyfield":
                    showMessage(false, "Hãy điền đủ các trường", carrier);
                    break;
                case "success":
                    showMessage(true, "Đăng nhập thành công", carrier);
                    window.location.href = "/";
                    break;
                case "failed":
                    showMessage(
                        false,
                        "Email hoặc mật khẩu của bạn có thể đã sai",
                        carrier
                    );
                    password.val("");
                    break;
                case "blocked":
                    showMessage(false,
                        "Tài khoản này đang bị khóa.",
                        carrier);
                    $('#unblockRequest').removeClass('d-none');
                    $('#unblockRequest').css('display', 'BLOCK!IMPORTANT');
                    break;
                default:
                    showMessage(false, "Đã xảy ra lỗi", carrier);
                    password.val("");
                    break;
            }
        },
        error: function (request, status, error) {
            console.log(request.responseText);
            console.log(request.status);
            console.log(status);
            showMessage(false, "Đã có lỗi xảy ra với hệ thống", carrier);
        },
        complete: function () {
            btn.prop("disabled", false);
        },
    });
});
$("#forgotpass-form").submit(function (e) {
    e.preventDefault();
    var btn = $("#btn-forgotpass");
    var carrier = $("#show-forgotpass-message");
    $.ajax({
        type: "POST",
        data: $(this).serialize(),
        contentType: "application/x-www-form-urlencoded",
        accept: "text/plain",
        url: "/forgot-pass",
        beforeSend: function () {
            showMessage(true, "Đang xử lý", carrier);
            btn.prop("disabled", true);
        },
        success: function (result) {
            switch (result) {
                case "noexistemail":
                    showMessage(
                        false,
                        "Tài khoản của bạn không tồn tại trong hệ thống",
                        carrier
                    );
                    break;
                case "success":
                    showMessage(true, "Hãy kiểm tra email của bạn", carrier);
                    setTimeout(function () {
                        $("#forgetPass").modal("hide");
                        $("#resetPass").modal("show");
                    }, 2000);
                    break;
                case "unactive":
                    showMessage(false, "Tài khoản của bị đã bị khóa", carrier);
                    break;
                case "failed":
                    showMessage(
                        false,
                        "Đã xảy ra lỗi khi gửi email hãy thử lại",
                        carrier
                    );
                    break;
                default:
                    showMessage(false, "Đã xảy ra lỗi", carrier);
                    break;
            }
        },
        error: function (request, status, error) {
            showMessage(false, "Đã có lỗi xảy ra với hệ thống", carrier);
        },
        complete: function () {
            btn.prop("disabled", false);
        },
    });
});
$("#resetpass-form").submit(function (e) {
    e.preventDefault();
    console.log($(this).serialize());
    var btn = $("#btn-resetpass");
    var carrier = $("#show-resetpass-message");
    $.ajax({
        type: "POST",
        data: $(this).serialize(),
        contentType: "application/x-www-form-urlencoded",
        accept: "text/plain",
        url: "/reset-pass",
        beforeSend: function () {
            showMessage(true, "Đang xử lý", carrier);
            btn.prop("disabled", true);
        },
        success: function (result) {
            switch (result) {
                case "emptyfield":
                    showMessage(false, "Hãy điền đủ vào các trường", carrier);
                    break;
                case "success":
                    showMessage(true, "Đổi mật khẩu thành công", carrier);
                    setTimeout(function () {
                        $("#resetPass").modal("hide");
                        $("#signInModel").modal("show");
                    }, 1500);
                    break;
                case "validpass":
                    showMessage(
                        false,
                        "Mật khẩu phải nhiều hơn 8 ký tự,có ít nhất 1 ký thường,hoa,số,đặc biệt",
                        carrier
                    );
                    resetResetPassIntput();
                    break;
                case "notequate":
                    showMessage(false, "Mật khẩu nhập lại không trùng khớp", carrier);
                    resetResetPassIntput();
                    break;
                case "failcode":
                    showMessage(false, "Reset code sai hoặc đã hết hạn", carrier);
                    break;
                default:
                    showMessage(false, "Đã xảy ra lỗi", carrier);
                    break;
            }
        },
        error: function (request, status, error) {
            showMessage(false, "Đã có lỗi xảy ra với hệ thống", carrier);
        },
        complete: function () {
            btn.prop("disabled", false);
        },
    });
});

//UNBLOCK
$("#unblockRequestForm").submit(function (e) {
    e.preventDefault();
    var btn = $("#btn-unlock-submit");
    var carrier = $("#show-forgotpass-message2");
    $.ajax({
        type: "POST",
        data: $(this).serialize(),
        contentType: "application/x-www-form-urlencoded",
        accept: "text/plain",
        url: "/unblock-account",
        beforeSend: function () {
            showMessage(true, "Đang xử lý", carrier);
            btn.prop("disabled", true);
        },
        success: function (result) {
            switch (result) {
                case "noexistemail":
                    showMessage(
                        false,
                        "Tài khoản của bạn không tồn tại trong hệ thống",
                        carrier
                    );
                    break;
                case "success":
                    showSuccessMessage("Thành công!","<span style=\"font-weight: normal\"> Chúng tôi đã nhận được yêu cầu của bạn.<p>Chúng tôi sẽ sớm hồi đáp cho bạn, hãy kiểm tra email bạn nhé!</p></span>");
                    $('#requestUnblockForm').modal('hide');
                    $('#password').val("");
                    $('#email').val("");
                    $('#show-login-message').css('display','none');
                    $('#unblockRequest').css('display', 'none');
                    break;
                case "failed":
                    showMessage(
                        false,
                        "Đã xảy ra lỗi khi gửi email hãy thử lại",
                        carrier
                    );
                    break;
                case "ready":
                    showMessage(
                        false,
                        "Tài khoản của bạn đã mở khóa, hãy thử đăng nhập lại bạn nhé!",
                        carrier
                    );
                    break;
                case "failedverify":
                    showMessage(
                        false,
                        "Tài khoản chưa được xác thực, hãy kiểm tra email hoặc nhấn gửi mã xác thực email tại trang quản lý cá nhân bạn nhé!",
                        carrier
                    );
                    break;
                default:
                    showMessage(false, "Đã xảy ra lỗi", carrier);
                    break;
            }
        },
        error: function (request, status, error) {
            showMessage(false, "Đã có lỗi xảy ra với hệ thống", carrier);
        },
        complete: function () {
            btn.prop("disabled", false);
        },
    });
});
$(document).ready(function() {
    $("#show_hide_password a").on('click', function(event) {
        event.preventDefault();
        if($('#show_hide_password input').attr("type") == "text"){
            $('#show_hide_password input').attr('type', 'password');
            $('#show_hide_password i').addClass( "fa-eye-slash" );
            $('#show_hide_password i').removeClass( "fa-eye" );
        }else if($('#show_hide_password input').attr("type") == "password"){
            $('#show_hide_password input').attr('type', 'text');
            $('#show_hide_password i').removeClass( "fa-eye-slash" );
            $('#show_hide_password i').addClass( "fa-eye" );
        }
    });
});