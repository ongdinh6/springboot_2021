var apiAllProducts = 'http://localhost:8080/admin/products-manage'
var currentAPI = 'http://localhost:8080/admin/products-manage'
var textValueFindBy = $('#textValueFindBy').val();

$('#btnFindBy').click(function () {
    textValueFindBy = $('#textValueFindBy').val();
    if (textValueFindBy !== "") {
        apiAllProducts += "?find=" + textValueFindBy;
    }
    $.ajax({
        url: apiAllProducts,
        success: function (rs) {
            window.location.href = apiAllProducts
            apiAllProducts = currentAPI;
        }
    })
})
if (textValueFindBy !== "") {
    $(".page-link").each(function () {
        $(this).prop('href', $(this).prop('href') + "&find=" + textValueFindBy)
    });
}

//upload product img
window.addEventListener('load', function () {
    document.querySelector('input[type="file"]').addEventListener('change', function () {
        if (this.files && this.files[0]) {
            var img = document.querySelector('#fileImgNewProduct');
            img.onload = () => {
                URL.revokeObjectURL(img.src);  // no longer needed, free memory
            }

            img.src = URL.createObjectURL(this.files[0]); // set src to blob url
            $('#fileImgNewProduct').text(img.src);
            $('#fileImgNewProduct').prop('href', img.src);
        }
    });
});

var ckeditor = ''
$(document).ready(function () {
    ckeditor = CKEDITOR
        .replace(
            'inputProductImgDes1',
            {
                height: 400,
                filebrowserUploadUrl: '/admin/products-manage/upload_ckeditor',
                filebrowserBrowseUrl: '/admin/products-manage/filebrowser',
                filebrowserWindowWidth: 800,
                filebrowserWindowHeight: 500
            });

})

//element all a product
var img01 = '';
var img02 = '';
var img03 = '';
var img04 = '';
var title01 = '';
var title02 = '';
var title03 = '';
var title04 = '';
var script01 = '';
var script02 = '';
var script03 = '';
var script04 = '';

$('#btnSubmitAddNewProduct').click(function () {
    var b = ckeditor.getData();
    var htmlText = `${b}`
    // $('.content-for-ckeditor').html(htmlText)
    // var titles = $('.content-for-ckeditor').find($('h1'))
    // var imgs = $('.content-for-ckeditor').find($('img'))
    // var scripts = $('.content-for-ckeditor').find($('p'))
    //
    // allTitles(titles)
    // allScript(scripts)
    // allImgDes(imgs)

    //ajax post new product
    var productInfo = getInfoProduct(htmlText);
    console.log(JSON.stringify(productInfo))
    $.ajax({
        type: 'POST',
        contentType:'application/json',
        accept: 'application/json',
        data: JSON.stringify(productInfo),
        url: '/admin/products-manage/new',
        success: function (rs) {
            if(rs === "error") showErrorMessage("Lỗi", "Hệ thống đang gặp sự cố. Vui lòng thử lại sau!")
            if(rs === "success"){
                showSuccessMessage("Thêm thành công!", "Sản phẩm đã được thêm vào hệ thống thành công.")
                var seconds = 1;
                setInterval(function () {
                    if (seconds == 0) {
                        window.location.href = '/admin/products-manage'
                    }
                    seconds--;
                }, 1000);
            }
        }
    })


})

function allTitles(titles) {
    $(titles).each(function (index) {
        switch (index) {
            case 0:
                title01 = $(this).text();
                break;
            case 1:
                title02 = $(this).text();
                break;
            case 2:
                title03 = $(this).text();
                break;
            case 3:
                title04 = $(this).text();
                break;
        }
    });
}

function allImgDes(imgs) {
    $(imgs).each(function (index) {
        switch (index) {
            case 0:
                img01 = $(this).prop('src');
                break;
            case 1:
                img02 = $(this).prop('src');
                break;
            case 2:
                img03 = $(this).prop('src');
                break;
            case 3:
                img04 = $(this).prop('src');
                break;
        }
    });
}

function allScript(scripts) {
    $(scripts).each(function (index) {
        console.log("scripts = "+index+": "+$(this).text())
        switch (index) {
            case 0:
                script01 = $(this).text();
                break;
            case 2:
                script02 = $(this).text();
                break;
            case 4:
                script03 = $(this).text();
                break;
            case 6:
                script04 = $(this).text();
                break;
        }
    });
}

function getInfoProduct(longText) {
    var name = $('#inputProductName').val();
    let price = $('#inputProductPrice').val();
    var img = $('#btnUploadImage').val();
    let brandID = $('#inputProductBrand').val()
    let ramID = $('#inputProductRam').val();
    let romID = $('#inputProductRom').val();
    let pinID = $('#inputProductPin').val();
    var size = $('#inputProductSize').val();
    var selfieCamera = $('#inputProductSelfieCamera').val();
    var mainCamera = $('#inputProductMainCamera').val();
    let active = $('#inputProductActive').val();


    var productInfo = {
        "name": name,
        "price":price,
        "img":img,
        "brandID": brandID,
        "ramID":ramID,
        "romID":romID,
        "pinID":pinID,
        "size":size,
        "selfieCamera":selfieCamera,
        "mainCamera":mainCamera,
        "active":active,
        "longDescription":longText
        // "img01":img01,
        // "img02":img02,
        // "img03":img03,
        // "img04":img04,
        // "title01":title01,
        // "title02":title02,
        // "title03":title03,
        // "title04":title04,
        // "script01":script01,
        // "script02":script02,
        // "script03":script03,
        // "script04":script04
    }
    return productInfo;
}

//delete product
function deleteProduct(id) {
    $.ajax({
        type:'DELETE',
        url:'/admin/products-manage/'+id,
        success: function (rs) {
            if(rs === "error") showErrorMessage("Lỗi", "Hệ thống đang xảy ra lỗi. Vui lòng thực hiện sau!")
            if(rs === "success") {
                showSuccessMessage("Thành công", "Sản phẩm đã được xóa khỏi hệ thống.");
                var seconds = 1;
                setInterval(function () {
                    if (seconds == 0) {
                        window.location.href = '/admin/products-manage'
                    }
                    seconds--;
                }, 1000);
            }
        }
    })
}
let idDelete = 0;
$('.btnRemove').click(function () {
    idDelete = $(this).prop('id').split('-')[1];
    var idModalDelete =  $(this).prop('data-target');
    $(this).prop('data-target').append(id);
    idModalDelete.append(id);
})
$('#btnConfirmDelete').click(function () {
    deleteProduct(idDelete)
})