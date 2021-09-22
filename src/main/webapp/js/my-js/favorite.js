$(".product-favorite").on("click", function (e) {
  e.preventDefault();
  var absoluteUrl = new URL(
    window.location.protocol + "//" + window.location.host
  );

  console.log(absoluteUrl.toString());
  var productId = $(this).data("product");
  if ($(this).hasClass("active") == false) {
    absoluteUrl.pathname = "/user/favorite/add";
    $.ajax({
      context: this,
      type: "POST",
      url: absoluteUrl.toString(),
      data: { productId: productId },
      success: function (response) {
        switch (response) {
          case "hasFavoriteProduct":
            showWarningMessage(
              "Đã yêu thích",
              "Bạn đã có thêm sản phẩm yêu thích này"
            );
            $(this).addClass("active");
            break;
          case "noExist":
            showWarningMessage(
              "Sản phẩm không tồn tại",
              "Sản phẩm mà bạn muốn thêm vào không tồn tại"
            );
            break;
          case "error":
            showErrorMessage(
              "Hệ thống xảy ra lỗi",
              "Mong bạn hãy thử lại hệ thống đang xảy ra lỗi"
            );
            break;
          default:
            showSuccessMessage(
              "Thêm thành công",
              "Sản phẩm đã được vào danh sách yêu thích của bạn"
            );
            $(this).addClass("active");
            break;
        }
      },
    });
  } else {
    absoluteUrl.pathname = "/user/favorite/delete";
    $.ajax({
      context: this,
      type: "POST",
      url: absoluteUrl.toString(),
      data: { productId: productId },
      success: function (response) {
        switch (response) {
          case "hasNotFavoriteProduct":
            showWarningMessage(
              "Chưa yêu thích",
              "Bạn chưa yêu thích sản phẩm này"
            );
            $(this).removeClass("active");
            break;
          case "error":
            showErrorMessage(
              "Hệ thống xảy ra lỗi",
              "Mong bạn hãy thử lại hệ thống đang xảy ra lỗi"
            );
            break;
          default:
            showSuccessMessage(
              "Xoá thành công",
              "Sản phẩm đã được xóa khỏi danh sách yêu thích của bạn"
            );
            $(this).removeClass("active");
            break;
        }
      },
    });
  }
});
function countRows() {
  var rows = document.querySelectorAll("tbody tr");
  return rows.length;
}
$(".remove-favorite").on("click", function (e) {
  e.preventDefault();
  console.log(countRows());
  var productId = $(this).data("product");
  $.ajax({
    context: this,
    type: "POST",
    url: "/user/favorite/delete",
    data: { productId: productId },
    success: function (response) {
      switch (response) {
        case "hasNotFavoriteProduct":
          showWarningMessage(
            "Chưa yêu thích",
            "Bạn chưa yêu thích sản phẩm này"
          );
          $(this).closest("tr").remove();
          if (countRows() == 0) {
            window.location.href = "/user/favorite";
          }
          break;
        case "error":
          showErrorMessage(
            "Hệ thống xảy ra lỗi",
            "Mong bạn hãy thử lại hệ thống đang xảy ra lỗi"
          );
          break;
        default:
          showSuccessMessage(
            "Xoá thành công",
            "Sản phẩm đã được xóa khỏi danh sách yêu thích của bạn"
          );
          $(this).closest("tr").remove();
          if (countRows() == 0) {
            window.location.href = "/user/favorite";
          }
          break;
      }
    },
  });
});
