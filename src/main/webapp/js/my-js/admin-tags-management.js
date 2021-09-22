$(document).ready(function () {
    $('.error').css('color', 'red');

})
//brands
$('.btnRemoveBrand').click(function () {
    let id = $(this).attr('value');
    deleteByName(id, 'brands');
})

function deleteByName(id, name) {
    $.ajax({
        type: 'DELETE',
        url: '/admin/tags-manage/' + name + '/' + id,
        success: function (rs) {
            if (rs === "fail") showErrorMessage("Thất bại!", "Thông tin tag không hợp lệ. Không thể tìm thấy!");
            else {
                showSuccessMessage("Thành công", "Hệ thống thay đổi hiển thị thành công.")
                var seconds = 1;
                setInterval(function () {
                    if (seconds == 0) {
                        window.location.href = '/admin/tags-manage/' + name;
                    }
                    seconds--;
                }, 1000);
            }
        }
    })
}

//rams
$('.btnRemoveRams').click(function () {
    let id = $(this).attr('value');
    deleteByName(id, 'rams');
})
//roms
$('.btnRemoveRoms').click(function () {
    let id = $(this).attr('value');
    deleteByName(id, 'roms');
})

//pins
$('.btnRemovePins').click(function () {
    let id = $(this).attr('value');
    deleteByName(id, 'pins');
})

//update tags info
//brands
$('.btnUpdateInfoTag').click(function () {
    let id = $(this).attr('value');
    var obj = new FormData();
    obj.append("id", id);
    obj.append("name",$('#inputBrandNameEdit'+id).val());
    obj.append("logo",file_upload);
    obj.append("active",$('#activeBrandEdit'+id).val());
    let error = 0;
    if($('#imgUploadEdit'+id).val() === ''){
        error += 1;
        $('.error-img-tags').text('Upload hình ảnh ở đây!');
    }else{
        error -= 1;
    }
    if($('#inputBrandNameEdit'+id).val()==='') {
        error +=1;
        $('.error-name-tags').text('Không được bỏ trống trường này!');
    }else{
        error -=1;
    }
        updateInfo('brands', id, obj);
})

//function update info
function updateInfo(tagName, id, obj){
    $.ajax({
        type: 'PUT',
        data: obj,
        contentType: false,
        processData:false,
        url: tagName+'/'+id,
        success: function (rs) {
            if (rs === "fail") showErrorMessage("Thất bại!", "Thông tin tag không hợp lệ. Không thể tìm thấy!");
            else {
                showSuccessMessage("Thành công", "Hệ thống thay đổi thông tin thành công.")
                var seconds = 1;
                setInterval(function () {
                    if (seconds == 0) {
                        window.location.href = '/admin/tags-manage/' + tagName;
                    }
                    seconds--;
                }, 1000);
            }
        }
    })
}
var file_upload;
function previewFile(id) {//show-off image on views
    const preview = document.querySelector('#img'+id);
    if ($("#imgUploadEdit"+id)[0].files.length > 0) {
        file_upload = $("#imgUploadEdit"+id)[0].files[0]
    } else {
        // no file chosen!
    }
    const file = file_upload;
    const reader = new FileReader();

    reader.addEventListener("load", function () {
        // convert image file to base64 string
        preview.src = reader.result;
    }, false);

    if (file) {
        reader.readAsDataURL(file);
    }
}


//add new tags
$('.btnAddTagsSubmit').click(function () {
    var name = $(this).attr('value');
    var capacity = $('#inputCapacity').val();
    var active = $('#inputActive').val();
    var data = {
        "name":name,
        "capacity":capacity,
        "active":active
    }
    //call
    addNewTags(name, data);
})
function addNewTags(name, data){
    $.ajax({
        type:'POST',
        contentType: 'application/json;charset=UTF-8',
        data: JSON.stringify(data),
        url: 'tags/new',
        success: function (rs) {
            if (rs === "fail") showErrorMessage("Thất bại!", "Thông tin tag không hợp lệ. Không thể tìm thấy!");
            else {
                showSuccessMessage("Thành công", "Lưu thông tin tag thành công.")
                var seconds = 1;
                setInterval(function () {
                    if (seconds == 0) {
                        window.location.href = '/admin/tags-manage/' + name;
                    }
                    seconds--;
                }, 1000);
            }
        }
    })
}

//update rams, roms, pins
$('.btnTagsEdit').click(function () {
    let id = $(this).attr('value').split('-')[1];
    var name = $(this).attr('value').split('-')[0];
    var capacity = $('#inputCapacity'+id).val();
    var active = $('#inputActive'+id).val();
    var data = {
        "id":id,
        "name":name,
        "capacity":capacity,
        "active":active
    }
    //
    updateRRP(name, id, data);

})
function updateRRP(name, id, data){
    $.ajax({
        type:'PUT',
        contentType: 'application/json;charset=UTF-8',
        data: JSON.stringify(data),
        url: name+'/'+id,
        success: function (rs) {
            if (rs === "fail") showErrorMessage("Thất bại!", "Thông tin tag không hợp lệ. Không thể tìm thấy!");
            else {
                showSuccessMessage("Thành công", "Hệ thống thay đổi thông tin thành công.")
                var seconds = 1;
                setInterval(function () {
                    if (seconds == 0) {
                        window.location.href = '/admin/tags-manage/' + name;
                    }
                    seconds--;
                }, 1000);
            }
        }
    })
}