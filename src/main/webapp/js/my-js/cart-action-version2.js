$('.btnAddToCart').click(function () {
    var atDetail = document.querySelector("#quantity-product-detail");
    let amount = 1;
    if (atDetail) {
        amount = $('#quantity-product-detail').val();
    }
    var cartItemRequest = {
        "productID": $(this).val(),
        "amount": amount
    }
    $.ajax({
        type: 'POST',
        contentType: 'application/json',
        accept: 'application/json',
        data: JSON.stringify(cartItemRequest),
        url: '/api/cart',
        success: function (rs) {
            showSuccess();
            renderDATA(rs);
        }
    })
})

function renderDATA(data) {
    var cart = JSON.stringify(data);
    var listJSON = JSON.parse(cart);
    var items = listJSON.listItems.map(function (i) {
        let priceByProduct = formatter.format(i.totalPrice)
        return `
                            <li class="cart-item">
                                    <a href= "#" class="photo">
                                    <img src="${i.productImg}" class="cart-thumb"></a>
                                    <h6><a href="#"> ${i.productName} </a></h6>
                                    <p>${i.amount}x - <span class="product-price li-price">
                                        ${priceByProduct} 
                                    </span></p>
                              </li>`
    })
    $('.cart-list').html(items);
    $('.total-cart').html(formatter.format(listJSON.totalAll));
    $('#sumOfCart').text(listJSON.amount);
}

$(function () {
    $.ajax({
        type: 'GET',
        accept: 'application/json',
        url: '/api/cart',
        success: function (rs) {
            renderDATA(rs);
            renderCartPage(rs);
            renderDATACheckoutPage(rs);
        }
    })
})


//load all cart for cart page
function renderCartPage(data) {
    var cart = JSON.stringify(data);
    var listJSON = JSON.parse(cart);
    if (listJSON.amount == 0) {
        var cartEmpty = `
             <div class="container m-auto text-center">
                   <h2 class="text-dark font-weight-bold">Giỏ hàng hiện đang trống. Hãy thêm một vài sản phẩm bạn nhé!</h2>
                <div class="img m-auto">
                    <img src="../../../images/cam-ket/empty-cart.png" height="80" width="80"/>
                </div>
                <div class="for-btn p-5">
                    <a class="btn hvr-hover text-light" href="/product">Tiếp tục mua sắm</a>
                </div>
            </div>
            `
        $('.cart-box-main').html(cartEmpty);
        $('body').css('padding-right', 0);
        $('body').removeClass('modal-open');
        $('div.modal-backdrop.fade.show').remove();
    } else {
        var items = listJSON.listItems.map(function (cartItem) {
            var priceProduct = formatter.format(cartItem.priceProduct);
            var totalPriceByProduct = formatter.format(cartItem.totalPrice);
            return `
            <tr class="text-center tr-update tr${cartItem.productID}">
                <td class="thumbnail-img">
                    <a href="#">
                        <img class="img-fluid" src="${cartItem.productImg}" alt=""/>
                     </a>
                </td>
                <td class="text-left font-weight-bold text-dark">
                    <a class="product-name" text="${cartItem.productName}"></a>
                </td>
                <td class="price-pr">
                    <p class="product-price current-price-product" id="${cartItem.productID}">${priceProduct}</p>
                </td>
                <td class="quantity-box">
                    <input type="number" size="4" value="${cartItem.amount}" min="1" step="1" class="c-input-text qty text"></td>
                <td class="total-pr">
                     <p class="product-price total-by-product" text="${cartItem.totalPrice}" id="totalProductPriceAfterUpdate${cartItem.productID}">${totalPriceByProduct}</p>
                </td>
                <td class="remove-pr">
                    <a href="#" data-toggle="modal" class="remove-action" alt="${cartItem.totalPrice}"
                        data-target="#removeCartItemModal" value="${cartItem.productID}"
                           name="${cartItem.amount}">
                        <i class="fas fa-times" th:value="${cartItem.productID}"></i>
                    </a>
                </td>
            </tr>`
        });
        $('#tbody-cart').html(items);
        $('.total-all-price').text(formatter.format(listJSON.totalAll));
        $('.last-price').text(formatter.format(listJSON.lastPrice));
    }
}

//update amount cart item
$("tbody").on("change", ".tr-update", function () {
    var productID = $(this).find('p.product-price.current-price-product').prop('id');
    var amount = $(this).find('input.c-input-text.qty.text').val();
    $.ajax({
        type: 'PUT',
        contentType: 'application/json;charset=UTF-8',
        data: amount,
        accept: 'application/json',
        url: '/api/cart/' + productID,
        success: function (rs) {
            renderCartPage(rs);
            renderDATA(rs);
        }
    })
})

//delete cart item
var cartID = 0;
$("tbody").on("click", ".remove-action", function () {
    cartID = $(this).attr('value');
    $('#btnDeleteModalConfirm').prop('value', cartID)
})

$('#btnDeleteModalConfirm').click(function () {
    cartID = $(this).attr('value')
    $.ajax({
        type: 'DELETE',
        url: '/api/cart/' + cartID,
        success: function (rs) {
            $('#removeCartItemModal').modal('toggle');
            if (rs === null) showFailDelete();
            renderCartPage(rs);
            renderDATA(rs);
            deleteSuccess();
        }
    })
})


function deleteSuccess() {
    toast({
        type: 'success',
        title: "Xóa thành công!",
        message: "Sản phẩm vừa chọn đã được xóa khỏi giỏ hàng.",
        duration: 3000
    })
}

function showFailDelete() {
    toast({
        title: 'Thất bại!',
        type: "error",
        message: "Hệ thống đang xảy ra lỗi. Không thể xóa.",
        duration: 3000
    })
}

//checkout page
function renderDATACheckoutPage(data) {
    var cart = JSON.stringify(data);
    var listJSON = JSON.parse(cart);
    var items = listJSON.listItems.map(function (i) {
        let priceByProduct = formatter.format(i.totalPrice)
        return `<div class="media-body">
                     <div class="row">
                         <div class="col-3">
                             <a href="">
                               <img src="${i.productImg}" class="img-fluid" alt="">
                             </a>
                          </div>
                         <div class="col-9 text-left">
                            <a href="">${i.productName}</a>
                               <div class="small text-muted">Giá: <span class="product-price">${formatter.format(i.priceProduct)}</span>
                                  <span class="mx-2">|</span> Số lượng: <span>1</span>
                               <span class="mx-2">|</span> Đơn Giá: <span class="product-price">${priceByProduct}</span>/cái
                               </div>
                               </div>
                     </div>
                  </div>`
        });
    $('#order-content').html(items);
    $('#totalAll').text(formatter.format(listJSON.totalAll));
    $('#discountPrice').text(formatter.format(listJSON.saledPrice));
    $('#shipCodPrice').text(formatter.format(0));
    $('#lastPrice1').text(formatter.format(listJSON.lastPrice));
    $('#lastPrice2').text(formatter.format(listJSON.lastPrice));

}