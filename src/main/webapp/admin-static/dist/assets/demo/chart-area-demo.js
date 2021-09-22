// Set new default font family and font color to mimic Bootstrap's default styling
// Chart.defaults.global.defaultFontFamily = '-apple-system,system-ui,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif';
// Chart.defaults.global.defaultFontColor = '#292b2c';

// Area Chart Example
// var ctx = document.getElementById("myAreaChart");
// var myLineChart = new Chart(ctx, {
//     type: 'line',
//     data: {
//         labels: ["Mar 1", "Mar 2", "Mar 3", "Mar 4", "Mar 5", "Mar 6", "Mar 7", "Mar 8", "Mar 9", "Mar 10", "Mar 11", "Mar 12", "Mar 13"],
//         datasets: [{
//             label: "Sessions",
//             lineTension: 0.3,
//             backgroundColor: "rgba(2,117,216,0.2)",
//             borderColor: "rgba(2,117,216,1)",
//             pointRadius: 5,
//             pointBackgroundColor: "rgba(2,117,216,1)",
//             pointBorderColor: "rgba(255,255,255,0.8)",
//             pointHoverRadius: 5,
//             pointHoverBackgroundColor: "rgba(2,117,216,1)",
//             pointHitRadius: 50,
//             pointBorderWidth: 2,
//             data: [10000, 30162, 26263, 18394, 18287, 28682, 31274, 33259, 25849, 24159, 32651, 31984, 38451],
//         }],
//     },
//     options: {
//         scales: {
//             xAxes: [{
//                 time: {
//                     unit: 'date'
//                 },
//                 gridLines: {
//                     display: false
//                 },
//                 ticks: {
//                     maxTicksLimit: 7
//                 }
//             }],
//             yAxes: [{
//                 ticks: {
//                     min: 0,
//                     max: 40000,
//                     maxTicksLimit: 5
//                 },
//                 gridLines: {
//                     color: "rgba(0, 0, 0, .125)",
//                 }
//             }],
//         },
//         legend: {
//             display: false
//         }
//     }
// });
// Bar Chart Example
// myLineBarChart = new Chart(ctxLineBarChart, {
//   type: "bar",
//   data: {
//     labels: monthYearArr,
//     datasets: [
//       {
//         label: "Thanh toán trực tiếp",
//         backgroundColor: "#25c2a0",
//         borderColor: "#25c2a0",
//         data: offProfits,
//       },
//       {
//         label: "Thanh toán trực tuyến",
//         backgroundColor: "#ff1a68",
//         borderColor: "#ff1a68",
//         data: onlProfits,
//       },
//     ],
//   },

//   options: {
//     layout: {
//       padding: {
//         left: 0,
//         right: 50,
//         top: 0,
//         bottom: 0,
//       },
//     },
//     scales: {
//       xAxes: [
//         {
//           maxBarThickness: 100,
//           // time: {
//           //     unit: 'month'
//           // },
//           gridLines: {
//             offsetGridLines: true,
//             display: false,
//           },
//           offset: true,
//           ticks: {
//             beginAtZero: true,
//             // maxTicksLimit: 6
//           },
//         },
//       ],
//       yAxes: [
//         {
//           ticks: {
//             beginAtZero: true,
//             callback: function (value) {
//               return nf.format(value);
//             },
//             // min: 0,
//             // max: 15000,
//             // maxTicksLimit: 5
//           },
//           gridLines: {
//             offsetGridLines: true,
//             display: true,
//           },
//         },
//       ],
//     },
//     legend: {
//       display: true,
//       position: "top",
//     },
//     tooltips: {
//       callbacks: {
//         label: function (tooltipItem, chart) {
//           var datasetLabel =
//             chart.datasets[tooltipItem.datasetIndex].label || "";
//           return (
//             datasetLabel + ": " + number_format(tooltipItem.yLabel, 0) + "đ"
//           );
//         },
//       },
//     },
//   },
// });
// var myPieChart = new Chart(ctxPieChart, {
//   type: "pie",
//   data: {
//     labels: nameBrands,
//     datasets: [
//       {
//         data: brandProfits,
//         // backgroundColor: ["#007bff", "#dc3545", "#ffc107", "#28a745"],
//         backgroundColor: ["#007bff", "#dc3545"],
//       },
//     ],
//   },
//   options: {},
// });
