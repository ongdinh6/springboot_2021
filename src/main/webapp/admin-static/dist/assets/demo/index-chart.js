// Set new default font family and font color to mimic Bootstrap's default styling
Chart.defaults.global.defaultFontFamily =
  '-apple-system,system-ui,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif';
Chart.defaults.global.defaultFontColor = "#292b2c";
var ctxLineBarChart = document.getElementById("myLineBarChart");
var ctxPieChart = document.getElementById("myPieChart");
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
function isNumeric(value) {
  return /^-?\d+$/.test(value);
}
function notNullStr(value) {
  return !isEmpty(value) && !isBlank(value) && !value.isEmpty();
}
function extractPieChartLabels(response) {
  var result = [];
  var lines = response.split("\r\n");
  for (let i = 0; i < lines.length; i++) {
    var tabs = lines[i].split("\t");
    result.push(tabs[0]);
  }
  return result;
}
function extractPieChartData(response) {
  var result = [];
  var lines = response.split("\r\n");
  for (let i = 0; i < lines.length; i++) {
    var tabs = lines[i].split("\t");
    result.push(tabs[1]);
  }
  return result;
}
function extractLBChartLabels(response) {
  var result = [];
  var lines = response.split("\r\n");
  for (let i = 0; i < lines.length; i++) {
    var tabs = lines[i].split("\t");
    result.push(tabs[0]);
  }
  return result;
}
function extractLBChartOffData(response) {
  var result = [];
  var lines = response.split("\r\n");
  for (let i = 0; i < lines.length; i++) {
    var tabs = lines[i].split("\t");
    result.push(tabs[1]);
  }
  return result;
}
function extractLBOnlData(response) {
  var result = [];
  var lines = response.split("\r\n");
  for (let i = 0; i < lines.length; i++) {
    var tabs = lines[i].split("\t");
    result.push(tabs[2]);
  }
  return result;
}

var myLineBarChart;
var myPieChart;

function resetPieChart(ctx, type, data, options) {
  if (myPieChart) {
    var ctxId = $(ctx).attr("id");
    var parentCtx = $(ctx).parent();
    parentCtx.html(parentCtx.html());
    myPieChart.destroy();
    ctx = document.getElementById(ctxId);
    myPieChart = new Chart(ctx, { type: type, data: data, options: options });
  } else {
    myPieChart = new Chart(ctx, { type: type, data: data, options: options });
  }
}
function resetLBChart(ctx, type, data, options) {
  if (myLineBarChart) {
    var ctxId = $(ctx).attr("id");
    var parentCtx = $(ctx).parent();
    parentCtx.html(parentCtx.html());
    myLineBarChart.destroy();
    ctx = document.getElementById(ctxId);
    myLineBarChart = new Chart(ctx, {
      type: type,
      data: data,
      options: options,
    });
  } else {
    myLineBarChart = new Chart(ctx, {
      type: type,
      data: data,
      options: options,
    });
  }
}
var optionsLineBarChart = {
  plugins: {
    labels: false,
  },
  layout: {
    padding: {
      left: 0,
      right: 50,
      top: 0,
      bottom: 0,
    },
  },
  scales: {
    xAxes: [
      {
        maxBarThickness: 100,

        gridLines: {
          offsetGridLines: true,
          display: false,
        },
        offset: true,
        ticks: {
          beginAtZero: true,
        },
      },
    ],
    yAxes: [
      {
        ticks: {
          beginAtZero: true,
          callback: function (value) {
            return nf.format(value);
          },
        },
        gridLines: {
          offsetGridLines: true,
          display: true,
        },
      },
    ],
  },
  legend: {
    display: true,
    position: "top",
  },
  tooltips: {
    callbacks: {
      label: function (tooltipItem, chart) {
        var datasetLabel = chart.datasets[tooltipItem.datasetIndex].label || "";
        return datasetLabel + ": " + number_format(tooltipItem.yLabel, 0);
      },
    },
  },
};

var dataLineBarChart = {
  labels: [],
  datasets: [
    {
      label: "Thanh toán trực tiếp",
      backgroundColor: "#25c2a0",
      fill: false,
      borderColor: "#25c2a0",
      data: [],
    },
    {
      label: "Thanh toán trực tuyến",
      backgroundColor: "#ff1a68",
      fill: false,
      borderColor: "#ff1a68",
      data: [],
    },
  ],
};
var optionsPieChart = {
  plugins: {
    labels: {
      render: "percentage",
      fontColor: function (data) {
        var rgb = hexToRgb(data.dataset.backgroundColor[data.index]);
        var threshold = 140;
        var luminance = 0.299 * rgb.r + 0.587 * rgb.g + 0.114 * rgb.b;
        return luminance > threshold ? "black" : "white";
      },
      precision: 2,
    },
  },
  tooltips: {
    callbacks: {
      // this callback is used to create the tooltip label
      label: function (tooltipItem, data) {
        // get the data label and data value to display
        // convert the data value to local string so it uses a comma seperated number
        var dataLabel = data.labels[tooltipItem.index];
        var value =
          ": " +
          number_format(
            data.datasets[tooltipItem.datasetIndex].data[tooltipItem.index],
            0
          );

        // make this isn't a multi-line label (e.g. [["label 1 - line 1, "line 2, ], [etc...]])
        if (Chart.helpers.isArray(dataLabel)) {
          // show value on first line of multiline label
          // need to clone because we are changing the value
          dataLabel = dataLabel.slice();
          dataLabel[0] += value;
        } else {
          dataLabel += value;
        }

        // return the text to display on the tooltip
        return dataLabel;
      },
    },
  },
};
var dataPieChart = {
  labels: [],
  datasets: [
    {
      data: [],
      backgroundColor: [],
    },
  ],
};
function showMessage(isSuccess, message, carrier) {
  if (isSuccess) {
    if (carrier.hasClass("text-danger")) carrier.removeClass("text-danger");
    carrier.addClass("text-success");
    carrier.hide().text(message).fadeIn("slow");
  } else {
    if (carrier.hasClass("text-success")) carrier.removeClass("text-success");
    carrier.addClass("text-danger");
    carrier.hide().text(message).fadeIn("slow");
  }
}
$("#line-bar-chart-form").submit(function (e) {
  e.preventDefault();
  var btn = $(this).find(":submit")[0];
  var carrier = $(this).find(".show-message");
  var chartType = $(this).find("[name='chart-type']")[0].value;
  var type = $(this).find("[name='type']")[0].value;
  var fromDate = $(this).find("[name='from-date']")[0].value;
  var toDate = $(this).find("[name='to-date']")[0].value;
  if (isNumeric(chartType) && isNumeric(type) && notNullStr(fromDate) && notNullStr(toDate)) {
    $.ajax({
      type: "POST",
      url: "/admin/line-bar-chart",
      data: { type: type, fromdate: fromDate, todate: toDate },
      beforeSend: function () {
        $(btn).prop("disabled", true);
      },
      success: function (response) {
        switch (response) {
          case "formatdate":
            showMessage(
              false,
              "Ngày bắt đầu và ngày kết thúc không hợp lệ và không được bỏ trống",
              carrier
            );
            break;
          case "not-today":
            showMessage(
              false,
              "Ngày bắt đầu và ngày kết thúc không được lớn hơn ngày hôm nay",
              carrier
            );
            break;
          case "lower-than-onemonth":
            showMessage(
              false,
              "Ngày bắt đàu và ngày kết thúc phải cách nhau một tháng",
              carrier
            );
            break;
          case "greater-than-enddate":
            showMessage(
              false,
              "Ngày bắt đầu không được lớn hơn ngày kết thúc",
              carrier
            );
            break;
          default:
            showMessage(true, "", carrier);
            dataLineBarChart.labels = extractLBChartLabels(response);
            dataLineBarChart.datasets[0].data = extractLBChartOffData(response);
            dataLineBarChart.datasets[1].data = extractLBOnlData(response);
            if (chartType == "1") {
              resetLBChart(
                ctxLineBarChart,
                "line",
                dataLineBarChart,
                optionsLineBarChart
              );
            } else {
              resetLBChart(
                ctxLineBarChart,
                "bar",
                dataLineBarChart,
                optionsLineBarChart
              );
            }
            break;
        }
      },
      error: function (request, status, error) {
        showMessage(false, "Đã có lỗi xảy ra trên server", carrier);
      },
      complete: function () {
        $(btn).prop("disabled", false);
      },
    });
  } else {
    showMessage(false, "Hãy điền đầy đủ form", carrier);
  }
});
$("#pie-chart-form").submit(function (e) {
  e.preventDefault();
  var btn = $(this).find(":submit")[0];
  var carrier = $(this).find(".show-message");
  var category = $(this).find("[name='category']")[0].value;
  var type = $(this).find("[name='type']")[0].value;
  var fromDate = $(this).find("[name='from-date']")[0].value;
  var toDate = $(this).find("[name='to-date']")[0].value;

  if (
    isNumeric(category) &&
    isNumeric(type) &&
    notNullStr(fromDate) &&
    notNullStr(toDate)
  ) {
    $.ajax({
      type: "POST",
      url: "/admin/pie-chart",
      data: {
        category: category,
        type: type,
        fromdate: fromDate,
        todate: toDate,
      },
      beforeSend: function () {
        $(btn).prop("disabled", true);
      },
      success: function (response) {
        switch (response) {
          case "formatdate":
            showMessage(
              false,
              "Ngày bắt đầu và ngày kết thúc không hợp lệ và không được bỏ trống",
              carrier
            );
            break;
          case "not-today":
            showMessage(
              false,
              "Ngày bắt đầu và ngày kết thúc không được lớn hơn ngày hôm nay",
              carrier
            );
            break;
          case "lower-than-onemonth":
            showMessage(
              false,
              "Ngày bắt đàu và ngày kết thúc phải cách nhau một tháng",
              carrier
            );
            break;
          case "greater-than-enddate":
            showMessage(
              false,
              "Ngày bắt đầu không được lớn hơn ngày kết thúc",
              carrier
            );
            break;
          default:
            var newOptions = clone(optionsPieChart);
            dataPieChart.datasets[0].data = extractPieChartData(response);
            dataPieChart.labels = extractPieChartLabels(response);
            dataPieChart.datasets[0].backgroundColor = ramdomColorArr(
              dataPieChart.datasets[0].data.length
            );
            resetPieChart(ctxPieChart, "pie", dataPieChart, newOptions);
            break;
        }
      },
      error: function (request, status, error) {
        showMessage(false, "Đã có lỗi xảy ra trên server", carrier);
      },
      complete: function () {
        $(btn).prop("disabled", false);
      },
    });
  } else {
    showMessage(false, "Hãy điền đầy đủ form", carrier);
  }
});

var nf = Intl.NumberFormat();
function number_format(number, decimals, dec_point, thousands_sep) {
  // *     example: number_format(1234.56, 2, ',', ' ');
  // *     return: '1 234,56'
  number = (number + "").replace(",", "").replace(" ", "");
  var n = !isFinite(+number) ? 0 : +number,
    prec = !isFinite(+decimals) ? 0 : Math.abs(decimals),
    sep = typeof thousands_sep === "undefined" ? "," : thousands_sep,
    dec = typeof dec_point === "undefined" ? "." : dec_point,
    s = "",
    toFixedFix = function (n, prec) {
      var k = Math.pow(10, prec);
      return "" + Math.round(n * k) / k;
    };
  // Fix for IE parseFloat(0.55).toFixed(0) = 0;
  s = (prec ? toFixedFix(n, prec) : "" + Math.round(n)).split(".");
  if (s[0].length > 3) {
    s[0] = s[0].replace(/\B(?=(?:\d{3})+(?!\d))/g, sep);
  }
  if ((s[1] || "").length < prec) {
    s[1] = s[1] || "";
    s[1] += new Array(prec - s[1].length + 1).join("0");
  }
  return s.join(dec);
}
function clone(obj) {
  if (null == obj || "object" != typeof obj) return obj;
  var copy = obj.constructor();
  for (var attr in obj) {
    if (obj.hasOwnProperty(attr)) copy[attr] = obj[attr];
  }
  return copy;
}
function ramdomColorArr(length) {
  var result = [];
  outer: while (result.length < length) {
    var color = Colors.random().rgb;
    for (let i = 0; i < result.length; i++) {
      if (color === result[i]) {
        continue outer;
      }
    }
    result.push(color);
  }
  return result;
}
function hexToRgb(hex) {
  var result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
  return result
    ? {
        r: parseInt(result[1], 16),
        g: parseInt(result[2], 16),
        b: parseInt(result[3], 16),
      }
    : null;
}
