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
$("#update-password-form").on("submit", function (e) {
  e.preventDefault();
  var btn = $("#submit");
  var carrier = $("#show-message");
  $.ajax({
    context: this,
    type: "POST",
    url: "/user/update-password",
    contentType: "application/json",
    data: JSON.stringify($(this).serializeObject()),
    beforeSend: function () {
      showMessage(true, "Đang xử lý", carrier);
      btn.prop("disabled", true);
    },
    success: function (response) {
      var errorBlocks = $(this).find(".help-block");
      for (let index = 0; index < errorBlocks.length; index++) {
        $(errorBlocks[index]).text("");
      }
      if (response == "ACCEPTED") {
        showMessage(true, "Cập nhật mật khẩu thành công", carrier);
        var inputs = $(this).find("input");
        for (let index = 0; index < inputs.length; index++) {
          $(inputs[index]).val("");
        }
      } else if (response == "failed") {
        showMessage(false, "Bạn hãy thử lại, đã xảy ra lỗi ở server", carrier);
      } else {
        // console.log(input);
        var errorBlocks = $(this).find(".help-block");
        for (let index = 0; index < errorBlocks.length; index++) {
          $(inputs[index]).val("");
        }
        showMessage(false, "Cập nhật thất bại", carrier);
        for (var propName in response) {
          var input = $(this).find("[name='" + propName + "']")[0];
          var errorBlock = $(input).parent().find(".help-block");
          $(errorBlock).hide().text(response[propName]).fadeIn("slow");
        }
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
$("#update-info-form").on("submit", function (e) {
  e.preventDefault();
  var btn = $("#submit");
  var carrier = $("#show-message");
  $.ajax({
    context: this,
    type: "POST",
    url: "/user/update-infor",
    contentType: "application/json",
    data: JSON.stringify($(this).serializeObject()),
    beforeSend: function () {
      showMessage(true, "Đang xử lý", carrier);
      btn.prop("disabled", true);
    },
    success: function (response) {
      var errorBlocks = $(this).find(".help-block");
      for (let index = 0; index < errorBlocks.length; index++) {
        $(errorBlocks[index]).text("");
      }
      console.log(response);
      if (response == "ACCEPTED") {
        showMessage(true, "Cập nhật thành công", carrier);
        var inputs = $(this).find("input");
        // for (let index = 0; index < inputs.length; index++) {
        //   $(inputs[index]).val("");
        // }
      } else if (response == "failed") {
        showMessage(false, "Bạn hãy thử lại, đã xảy ra lỗi ở server", carrier);
      } else {
        showMessage(false, "Cập nhật thất bại", carrier);
        for (var propName in response) {
          var input = $(this).find("[name='" + propName + "']")[0];
          var errorBlock = $(input).parent().find(".help-block");
          if (propName == "gender") {
            var errorBlock = $(input).parent().parent().find(".help-block");
          }
          $(errorBlock).hide().text(response[propName]).fadeIn("slow");
        }
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
