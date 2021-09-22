$("#signInModel").on("shown.bs.modal", function () {
    $('body,html').addClass("modal-open");
    // $(window).scrollTop(0);
}).on("hidden.bs.modal", function () {
    $('body,html').removeClass("modal-open");
});
$("#forgetPass").on("shown.bs.modal", function () {
    $('body,html').addClass("modal-open");
    // $(window).scrollTop(0);
}).on("hidden.bs.modal", function () {
    $('body,html').removeClass("modal-open");
});
$("#createAccountModel").on("shown.bs.modal", function () {
    $('body,html').addClass("modal-open");
    // $(window).scrollTop(0);
}).on("hidden.bs.modal", function () {
    $('body,html').removeClass("modal-open");
});

