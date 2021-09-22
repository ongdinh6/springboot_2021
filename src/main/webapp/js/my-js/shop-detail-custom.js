// $(".load-more").simpleLoadMore({
//     item: "div",
//     btnHTML:
//         '<p class="font-weight-bold text-center mt-3"><button class="btn hvr-hover text-light">Xem thêm</button></p>',
//     count: 1,
//     itemsToLoad: 5,
// });
// $(".reply-popup").click(function (e) {
//     e.preventDefault();
//     $(".reply-box").toggle();
// });
// $("textarea").autoResize();
var sampleCommentForm = $("#sample-comment-reply-form").clone();
var sampleComment = $("#sample-comment-reply").clone();
$("#sample-comment-reply-form").remove();
$("#sample-comment-reply").remove();
$("button.reply-popup").on("click", function () {
  var parent = $(this).parent();
  var commentBox=parent.parent();
  var newCommentForm = parent.next();
  if (parent.next().hasClass("reply-box")) {
    newCommentForm.remove();
  } else {
    newCommentForm = sampleCommentForm.clone();
    newCommentForm.removeAttr("id");
    parent.after(newCommentForm);
    newCommentForm.find("textarea").autoResize();
    var cancelBtn = newCommentForm.find(".btn-comment-cancel");
    var submitBtn = newCommentForm.find(".btn-comment-submit");
    submitBtn.attr("data-review-id", $(this).attr("data-review-id"));
    $(cancelBtn).on("click", function () {
      newCommentForm.remove();
    });
    $(submitBtn).on("click", function (e) {
      e.preventDefault();
      var reviewId = $(this).attr("data-review-id");
      var content = $(newCommentForm.find("[name=content]")[0]).val();
      console.log(content);
      $.ajax({
        type: "POST",
        url: "/user/comment/create",
        data: { reviewId: reviewId, content: content },
        beforeSend: function () {
          showWarningMessage("Hệ thống", "Đang xử lý");
          submitBtn.prop("disabled", true);
          cancelBtn.prop("disabled", true);
        },
        success: function (response) {
          switch (response) {
            case "emptyfield":
              showWarningMessage("Nội dung", "Bạn phải nhập nội dung");
              break;
            case "validreview":
              showErrorMessage(
                "Đánh giá sản phẩm",
                "Đánh giá mà bạn bình luận không tồn tại "
              );
              break;
            case "failed":
              showErrorMessage("Hệ thống", "Xảy ra lỗi khi lưu trữ dữ liệu");
              break;
            default:
              showSuccessMessage("Thành công", "Bình luận thành công");
              newCommentForm.remove();
              var newComment = sampleComment.clone();
              newComment.removeAttr("id");
              newComment.find("a").text(response["name"]);
              newComment.find(".comment-time").text(response["created-date"]);
              newComment.find("p").text(response["content"]);
              commentBox.append(newComment);
              break;
          }
        },
        error: function (request, status, error) {
          if (request.status == 403) {
            showErrorMessage(
              "Đăng Nhập",
              "Bạn phải đăng nhập để sử dụng chức năng này"
            );
          } else {
            showErrorMessage(
              "Hệ thống",
              "Hãy thử lại, hệ thống đang xảy ra lỗi"
            );
          }
        },
        complete: function () {
          submitBtn.prop("disabled", false);
          cancelBtn.prop("disabled", false);
        },
      });
    });
  }
});
