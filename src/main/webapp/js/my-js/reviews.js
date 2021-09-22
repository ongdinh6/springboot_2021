$("#rateYo").rateYo({
  starWidth: "40px",
  fullStar: true,
});
var $rateYo = $("#rateYo").rateYo();
$(".open-review-form").on("click", function (e) {
  e.preventDefault();
  $("#show-message").text("");
  const item = $(this).closest(".pending-review-order-detail");
  const modal = $("#review-modal");
  $("#review-modal").modal("show");
  modal.find("img").attr("src", $($(item).find("img")[0]).attr("src"));
  modal
    .find("h5")
    .text($($(item).find(".order-detail-product-name")[0]).text());
  modal
    .find("strong")
    .text($($(item).find(".order-detail-order-id")[0]).text());
  modal
    .find("small")
    .text(
      "Mua ngày " + $($(item).find(".account-box")[0]).attr("data-created-date")
    );
  $rateYo.rateYo("rating", 0);
  modal.find("textarea").val("");
  modal
    .find("#order-detail-id")
    .val($($(item).find(".account-box")[0]).attr("data-order-detail-id"));
});
function hasItemOnPage(){
  return $(".pending-review-order-detail").length==0;
}
$("#review-form").on("submit", function (e) {
  e.preventDefault();
  var btn = $("#submit");
  var carrier = $("#show-message");
  var orderDetailId = parseInt($(this).find("#order-detail-id").val());
  console.log(orderDetailId);
  var content = $(this).find("textarea").val();
  var stars = $rateYo.rateYo("rating");
  $.ajax({
    type: "POST",
    url: "/user/review/create",
    data: { orderDetailId: orderDetailId, content: content, stars: stars },
    beforeSend: function () {
      showMessage(true, "Đang xử lý", carrier);
      btn.prop("disabled", true);
    },
    success: function (response) {
      if (response == "validContent") {
        showMessage(false, "Bạn không thể bỏ trống nội dung", carrier);
      } else if (response == "validStar") {
        showMessage(false, "Hãy chọn sao để đánh giá chất lượng", carrier);
      } else if (response == "validId") {
        showMessage(
          false,
          "Sản phẩm này đã được đánh giá hoặc bạn chưa mua sản phẩm này",
          carrier
        );
      } else if (response == "failed") {
        showMessage(false, "Hệ thống xảy ra lỗi, bạn hãy thử lại", carrier);
      } else {
        showMessage(true, "Nhận xét thành công", carrier);
        setTimeout(function () {
          $("#review-modal").modal("hide");
          $("[data-order-detail-id="+orderDetailId+"]").parent().remove();
        }, 1000);
        if(hasItemOnPage()){
          window.location.href="/user/review/pending";
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
