const query = location.search;
setHrefForPages();
function setHrefForPages() {
  var locationParams = new URLSearchParams(query);
  if (locationParams.has("page")) locationParams.delete("page");
  $(".page-item a").each(function (index, element) {
    var intUrl = new URL(
      window.location.protocol +
        "//" +
        window.location.host +
        $(this).attr("href")
    );
    var pathname = intUrl.pathname;
    var params = new URLSearchParams(intUrl.search);
    locationParams.forEach(function (value, key) {
      params.append(key, value);
    });
    $(this).attr(
      "href",
      window.location.protocol +
        "//" +
        window.location.host +
        pathname +
        "?" +
        params.toString()
    );
  });
}

setValueSelectPickers();
String.prototype.isEmpty = function () {
  return this.length === 0 || !this.trim();
};
function isEmpty(str) {
  return !str || str.length === 0;
}

function isBlank(str) {
  return !str || /^\s*$/.test(str);
}

function isPositiveInteger(n) {
  return n >>> 0 === parseFloat(n);
}

function setValueSelectPicker(select, value) {
  select.val(value);
  select.selectpicker("refresh");
}

function setValueSelectPickers() {
  var params = new URLSearchParams(query);
  if (params.has("brand"))
    setValueSelectPicker($("#search-brand"), params.get("brand"));
  if (params.has("pin"))
    setValueSelectPicker($("#search-pin"), params.get("pin"));
  if (params.has("ram"))
    setValueSelectPicker($("#search-ram"), params.get("ram"));
  if (params.has("rom"))
    setValueSelectPicker($("#search-rom"), params.get("rom"));
  if (params.has("sort-type"))
    setValueSelectPicker($("#sort-type"), params.get("sort-type"));
  if (params.has("sort-order"))
    setValueSelectPicker($("#sort-order"), params.get("sort-order"));
}

function hasSortValue(sortType, sortOrder) {
  return sortType && sortOrder;
}

function hasOneSortValue(sortType, sortOrder) {
  return sortType || sortOrder;
}

function hasNameCategoryValue(brand, pin, ram, rom, name) {
  return brand || pin || ram || rom || name;
}

$("#search").on("click", function (e) {
  e.preventDefault();
  var brand = $("#search-brand").val();
  var pin = $("#search-pin").val();
  var ram = $("#search-ram").val();
  var rom = $("#search-rom").val();
  var name = $("#search-name").val();
  var sortType = $("#sort-type").val();
  var sortOrder = $("#sort-order").val();
  console.log();
  if (
    hasSortValue(sortType, sortOrder) ||
    hasNameCategoryValue(brand, pin, ram, rom, name)
  ) {
    var params = new URLSearchParams();
    if (
      hasOneSortValue(sortType, sortOrder) &&
      !hasSortValue(sortType, sortOrder)
    ) {
      showWarningMessage("Chọn sắp xếp","Bạn hãy chọn cả hai option sắp xếp để có thể sắp xếp");
    } else {
      if (isPositiveInteger(brand)) params.append("brand", brand);
      if (isPositiveInteger(pin)) params.append("pin", pin);
      if (isPositiveInteger(ram)) params.append("ram", ram);
      if (isPositiveInteger(rom)) params.append("rom", rom);
      if (!isEmpty(name) && !isBlank(name) && !name.isEmpty())
        params.append("name", name);
      if (hasSortValue(sortType, sortOrder)) {
        if (isPositiveInteger(sortType)) params.append("sort-type", sortType);
        if (isPositiveInteger(sortOrder))
          params.append("sort-order", sortOrder);
      }
      location.search = params.toString();
    }
  } else {
    showWarningMessage("Không có tiêu chí","Bạn chưa chọn một tiêu chí để tìm sản phẩm");
  }
});
