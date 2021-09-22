$(".content-div").hide();
$("#change").change(function () {
    $(".content-div").hide();
    $("#" + $(this).val()).show();
});